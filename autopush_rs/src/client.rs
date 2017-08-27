//! Managment of connected clients to a WebPush server
//!
//! This module is a pretty heavy work in progress. The intention is that
//! this'll house all the various state machine transitions and state management
//! of connected clients. Note that it's expected there'll be a lot of connected
//! clients, so this may appears relatively heavily optimized!

use std::io;
use std::marker;
use std::rc::Rc;

use futures::AsyncSink;
use futures::future::{result, err, loop_fn, Loop, ok, Either};
use futures::sync::mpsc;
use futures::{Stream, Sink, Future, Poll, Async};
use tokio_core::reactor::Timeout;
use time;
use uuid::Uuid;

use call;
use errors::*;
use protocol::{ClientMessage, ServerMessage, Notification};
use server::Server;
use util::timeout;

pub struct RegisteredClient {
    pub uaid: Uuid,
    pub tx: mpsc::UnboundedSender<Notification>,
}

// Represents a websocket client connection that may or may not be authenticated
pub struct Client<T> {
    webpush: Option<WebPushClient>,
    state: ClientState,
    srv: Rc<Server>,
    ws: T,
}

// Represent the state for a valid WebPush client that is authenticated
pub struct WebPushClient {
    uaid: Uuid,
    rx: mpsc::UnboundedReceiver<Notification>,
    flags: ClientFlags,
    message_month: String,
    unacked_direct_notifs: Vec<Notification>,
    unacked_stored_notifs: Vec<String>,
    // Highest version from stored, retained for use with increment
    // when all the unacked storeds are ack'd
    unacked_stored_highest: Option<String>,
}

pub struct ClientFlags {
    include_topic: bool,
    increment_storage: bool,
    check: bool,
    reset_uaid: bool,
    rotate_message_table: bool,
}

impl ClientFlags {
    fn new() -> ClientFlags {
        ClientFlags {
            include_topic: false,
            increment_storage: false,
            check: false,
            reset_uaid: false,
            rotate_message_table: false,
        }
    }

    pub fn none(&self) -> bool {
        // Indicate if none of the flags are true.
        match *self {
            ClientFlags {
                include_topic: false,
                increment_storage: false,
                check: false,
                reset_uaid: false,
                rotate_message_table: false,
            } => true,
            _ => false,
        }
    }
}

pub enum ClientState {
    WaitingForHello(Timeout),
    WaitingForProcessHello(MyFuture<call::HelloResponse>),
    WaitingForRegister(Uuid, MyFuture<call::RegisterResponse>),
    WaitingForUnRegister(Uuid, MyFuture<call::UnRegisterResponse>),
    FinishSend(Option<ServerMessage>, Option<Box<ClientState>>),
    Await,
    Done,
    ShutdownCleanup(Option<Error>),
}

impl<T> Client<T>
where
    T: Stream<Item = ClientMessage, Error = Error>
        + Sink<SinkItem = ServerMessage, SinkError = Error>
        + 'static,
{
    /// Spins up a new client communicating over the websocket `ws` specified.
    ///
    /// The `ws` specified already has ping/pong parts of the websocket
    /// protocol managed elsewhere, and this struct is only expected to deal
    /// with webpush-specific messages.
    ///
    /// The `srv` argument is the server that this client is attached to and
    /// the various state behind the server. This provides transitive access to
    /// various configuration options of the server as well as the ability to
    /// call back into Python.
    pub fn new(ws: T, srv: &Rc<Server>) -> Client<T> {
        let srv = srv.clone();
        let timeout = Timeout::new(srv.opts.open_handshake_timeout.unwrap(), &srv.handle).unwrap();
        Client {
            state: ClientState::WaitingForHello(timeout),
            webpush: None,
            srv: srv.clone(),
            ws: ws,
        }
    }

    fn transition(&mut self) -> Poll<ClientState, Error> {
        let next_state = match self.state {
            ClientState::WaitingForHello(ref mut timeout) => {
                match try_ready!(Combinators::input_with_timeout(&mut self.ws, timeout)) {
                    ClientMessage::Hello {
                        uaid: uaid,
                        use_webpush: Some(true),
                        ..
                    } => {
                        ClientState::WaitingForProcessHello(
                            self.srv.hello(&time::now(), uaid.as_ref()),
                        )
                    },
                    _ => return Err("Invalid message, must be hello".into()),
                }
            },
            ClientState::WaitingForProcessHello(ref mut response) => {
                match try_ready!(response.poll()) {
                    call::HelloResponse {
                        uaid: Some(uaid),
                        message_month: message_month,
                        reset_uaid: reset_uaid,
                        rotate_message_table: rotate_message_table,
                    } => {
                        let (tx, rx) = mpsc::unbounded();
                        let mut flags = ClientFlags::new();
                        flags.reset_uaid = reset_uaid;
                        flags.rotate_message_table = rotate_message_table;
                        self.webpush = Some(WebPushClient {
                            uaid: uaid,
                            flags: flags,
                            rx: rx,
                            message_month: message_month,
                            unacked_direct_notifs: Vec::new(),
                            unacked_stored_notifs: Vec::new(),
                            unacked_stored_highest: None,
                        });
                        self.srv.connect_client(
                            RegisteredClient { uaid: uaid, tx: tx },
                        );
                        let response = ServerMessage::Hello {
                            uaid: uaid.hyphenated().to_string(),
                            status: 200,
                            use_webpush: Some(true),
                        };
                        ClientState::FinishSend(Some(response), Some(Box::new(ClientState::Await)))
                    }
                    _ => return Err("Already connected elsewhere".into()),
                }
            },
            ClientState::FinishSend(None, None) => {
                return Err("Bad state, should not have nothing to do".into())
            },
            ClientState::FinishSend(None, ref mut next_state) => {
                try_ready!(self.ws.poll_complete());
                *next_state.take().unwrap()
            }
            ClientState::FinishSend(ref mut msg, ref mut next_state) => {
                let item = msg.take().unwrap();
                let ret = self.ws.start_send(item).chain_err(|| "unable to send")?;
                match ret {
                    AsyncSink::Ready => {
                        ClientState::FinishSend(None, Some(next_state.take().unwrap()))
                    },
                    AsyncSink::NotReady(returned) => {
                        *msg = Some(returned);
                        return Ok(Async::NotReady);
                    }
                }
            },
            ClientState::Await => {
                let webpush = self.webpush.as_mut().unwrap();
                match try_ready!(Combinators::input_or_notif(&mut self.ws, &mut webpush.rx)) {
                    Either::A(ClientMessage::Register {
                                  channel_id: channel_id,
                                  key: key,
                              }) => {
                        debug!("Got a register command!");
                        let uaid = webpush.uaid.clone();
                        let message_month = webpush.message_month.clone();
                        let channel_id_str = channel_id.hyphenated().to_string();
                        let fut = self.srv.register(
                            uaid.simple().to_string(),
                            message_month,
                            channel_id_str,
                            key,
                        );
                        ClientState::WaitingForRegister(channel_id, fut)
                    },
                    Either::A(ClientMessage::Unregister {
                                  channel_id: channel_id,
                                  code: code,
                              }) => {
                        debug!("Got a unregister command");
                        let uaid = webpush.uaid.clone();
                        let message_month = webpush.message_month.clone();
                        let channel_id_str = channel_id.hyphenated().to_string();
                        let fut = self.srv.unregister(
                            uaid.simple().to_string(),
                            message_month,
                            channel_id_str,
                            code.unwrap_or(200),
                        );
                        ClientState::WaitingForUnRegister(channel_id, fut)
                    },
                    Either::A(ClientMessage::Ack { updates: updates }) => {
                        for notif in updates.iter() {
                            if let Some(pos) = webpush.unacked_direct_notifs.iter().position(
                                |v| {
                                    v.channel_id == notif.channel_id && v.version == notif.version
                                },
                            )
                            {
                                webpush.unacked_direct_notifs.remove(pos);
                                continue;
                            };
                            if let Some(pos) = webpush.unacked_stored_notifs.iter().position(
                                |v| {
                                    v == &notif.version
                                },
                            )
                            {
                                webpush.unacked_stored_notifs.remove(pos);
                                continue;
                            };
                        }
                        ClientState::Await
                    },
                    Either::B(notif) => {
                        webpush.unacked_direct_notifs.push(notif.clone());
                        debug!("Got a notification to send, sending!");
                        ClientState::FinishSend(
                            Some(ServerMessage::Notification(notif)),
                            Some(Box::new(ClientState::Await)),
                        )
                    },
                    Either::A(_) => return Err("Invalid message".into()),
                }
            },
            ClientState::WaitingForRegister(channel_id, ref mut response) => {
                match try_ready!(response.poll()) {
                    call::RegisterResponse::Success { endpoint: endpoint } => {
                        let msg = ServerMessage::Register {
                            channel_id: channel_id,
                            status: 200,
                            push_endpoint: endpoint,
                        };
                        ClientState::FinishSend(Some(msg), Some(Box::new(ClientState::Await)))
                    },
                    call::RegisterResponse::Error { error_msg: msg, status: status, .. } => {
                        debug!("Got unregister fail, error: {}", msg);
                        let msg = ServerMessage::Register {
                            channel_id: channel_id,
                            status: status,
                            push_endpoint: "".into(),
                        };
                        ClientState::FinishSend(Some(msg), Some(Box::new(ClientState::Await)))
                    },
                    _ => return Err("woopsies, malfunction".into()),
                }
            },
            ClientState::WaitingForUnRegister(channel_id, ref mut response) => {
                debug!("Attempting to wait for unregister");
                match try_ready!(response.poll()) {
                    call::UnRegisterResponse::Success{ success: success } => {
                        debug!("Got the unregister response");
                        let msg = ServerMessage::Unregister {
                            channel_id: channel_id,
                            status: if success { 200 } else { 500 },
                        };
                        ClientState::FinishSend(Some(msg), Some(Box::new(ClientState::Await)))
                    },
                    call::UnRegisterResponse::Error { error_msg: msg, status: status, .. } => {
                        debug!("Got unregister fail, error: {}", msg);
                        let msg = ServerMessage::Unregister {
                            channel_id: channel_id,
                            status: status,
                        };
                        ClientState::FinishSend(Some(msg), Some(Box::new(ClientState::Await)))
                    },
                    _ => return Err("woopsies, malfunction".into()),
                }
            },
            ClientState::ShutdownCleanup(ref mut err) => {
                if let Some(err_obj) = err.take() {
                    debug!("Error for shutdown: {}", err_obj);
                };
                // If we made it past hello, do more cleanup
                if let Some(WebPushClient { uaid: uaid, .. }) = self.webpush {
                    self.srv.disconnet_client(&uaid);
                };
                ClientState::Done
            },
            _ => return Err("Transition didn't work".into()),
        };
        Ok(next_state.into())
    }
}

pub struct Combinators<T> {
    _marker: marker::PhantomData<T>,
}

impl<T> Combinators<T>
where
    T: Stream<Item = ClientMessage, Error = Error>
        + Sink<SinkItem = ServerMessage, SinkError = Error>
        + 'static,
{
    fn input_with_timeout(ws: &mut T, timeout: &mut Timeout) -> Poll<ClientMessage, Error> {
        let item = match timeout.poll()? {
            Async::Ready(t) => return Err("Client timed out".into()),
            Async::NotReady => {
                match ws.poll()? {
                    Async::Ready(None) => return Err("Client dropped".into()),
                    Async::Ready(Some(msg)) => Async::Ready(msg),
                    Async::NotReady => Async::NotReady,
                }
            }
        };
        Ok(item)
    }

    fn input_or_notif(
        ws: &mut T,
        queue: &mut mpsc::UnboundedReceiver<Notification>,
    ) -> Poll<Either<ClientMessage, Notification>, Error> {
        let item = match queue.poll() {
            Ok(Async::Ready(Some(notif))) => Either::B(notif),
            Ok(Async::Ready(None)) => return Err("Sending side went byebye".into()),
            Ok(Async::NotReady) => {
                match ws.poll()? {
                    Async::Ready(None) => return Err("Client dropped".into()),
                    Async::Ready(Some(msg)) => Either::A(msg),
                    Async::NotReady => return Ok(Async::NotReady),
                }
            },
            _ => return Err("Woah".into()),
        };
        Ok(Async::Ready(item))
    }
}

impl<T> Future for Client<T>
where
    T: Stream<Item = ClientMessage, Error = Error>
        + Sink<SinkItem = ServerMessage, SinkError = Error>
        + 'static,
{
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        loop {
            if let ClientState::Done = self.state {
                return Ok(().into());
            }
            match self.transition() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(next_state)) => self.state = next_state,
                Err(e) => self.state = ClientState::ShutdownCleanup(Some(e)),
            };
        }
    }
}

/// Helper future to wait for the first item on one of two streams, returning
/// the item and the two streams when done.
struct StreamNext<S1, S2> {
    left: Option<S1>,
    right: Option<S2>,
}

impl<S1, S2> StreamNext<S1, S2>
where
    S1: Stream,
    S2: Stream<Error = S1::Error>,
{
    fn new(s1: S1, s2: S2) -> StreamNext<S1, S2> {
        StreamNext {
            left: Some(s1),
            right: Some(s2),
        }
    }
}

impl<S1, S2> Future for StreamNext<S1, S2>
where
    S1: Stream,
    S2: Stream<Error = S1::Error>,
{
    type Item = Option<(Either<S1::Item, S2::Item>, S1, S2)>;
    type Error = S1::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let item = {
            let left = self.left.as_mut().unwrap();
            let right = self.right.as_mut().unwrap();
            match left.poll()? {
                Async::Ready(None) => return Ok(Async::Ready(None)),
                Async::Ready(Some(item)) => Either::A(item),
                Async::NotReady => {
                    match right.poll()? {
                        Async::Ready(None) => return Ok(Async::Ready(None)),
                        Async::Ready(Some(item)) => Either::B(item),
                        Async::NotReady => return Ok(Async::NotReady),
                    }
                }
            }
        };
        Ok(Async::Ready(Some((
            item,
            self.left.take().unwrap(),
            self.right.take().unwrap(),
        ))))
    }
}
