//! Managment of connected clients to a WebPush server
//!
//! This module is a pretty heavy work in progress. The intention is that
//! this'll house all the various state machine transitions and state management
//! of connected clients. Note that it's expected there'll be a lot of connected
//! clients, so this may appears relatively heavily optimized!

use std::io;
use std::marker;
use std::rc::Rc;

use futures::future::{result, err, loop_fn, Loop, ok, Either};
use futures::sync::mpsc;
use futures::{Stream, Sink, Future, Poll, Async};
use tokio_core::reactor::{Timeout};
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
    FinishSend(Option<Box<ClientState>>),
    Await,
    Done,
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
        let mut timeout = Timeout::new(
            srv.opts.open_handshake_timeout.unwrap(), &srv.handle)
            .unwrap();
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
                match try_ready!(input_with_timeout(&mut self.ws, timeout)) {
                    ClientMessage::Hello {
                        uaid: uaid,
                        use_webpush: Some(true),
                        ..
                    } => {
                        ClientState::WaitingForProcessHello(
                             self.srv.hello(
                                 &time::now(),
                                 uaid.as_ref(),
                             )
                        )
                    },
                    _ => return Err("Invalid message, must be hello".into())
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
                        });
                        self.srv.connect_client(RegisteredClient {
                            uaid: uaid,
                            tx: tx,
                            });
                        let response = ServerMessage::Hello {
                            uaid: uaid,
                            status: 200,
                            use_webpush: Some(true),
                        };
                        self.ws.start_send(response);
                        ClientState::FinishSend(Some(Box::new(ClientState::Await)))
                    }
                    _ => return Err("Already connected elsewhere".into())
                }
            },
            ClientState::FinishSend(ref mut next_state) => {
                try_ready!(self.ws.poll_complete());
                *next_state.take().unwrap()
            },
            ClientState::Await => {
                match try_ready!(self.ws.poll()) {
                    Some(msg) => return Err("shutdown".into()),
                    None => return Err("client wanted to shutdown".into()),
                }
            },
            _ => return Err("Transition didn't work".into())
        };
        Ok(next_state.into())
    }
}

fn input_with_timeout<T>(ws: &mut T, timeout: &mut Timeout) -> Poll<ClientMessage, Error>
where
    T: Stream<Item = ClientMessage, Error = Error>
        + Sink<SinkItem = ServerMessage, SinkError = Error>
        + 'static,
{
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
                return Ok(().into())
            }
            let next_state = try_ready!(self.transition());
            self.state = next_state;
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
