use std::marker;
use std::rc::Rc;

use futures::future::{result, err, loop_fn, Loop, ok, Either};
use futures::sync::mpsc;
use futures::{Stream, Sink, Future, Poll, Async};
use uuid::Uuid;

use call::PythonCall;
use errors::*;
use protocol::{ClientMessage, ServerMessage, Notification};
use server::Server;
use util::timeout;

pub struct Client<T> {
    inner: MyFuture<()>,
    _marker: marker::PhantomData<T>,
}

pub struct ClientState {
    pub uaid: Uuid,
    pub use_webpush: bool,
    pub channel_ids: Vec<Uuid>,
    pub tx: mpsc::UnboundedSender<Notification>,
    pub call: mpsc::UnboundedSender<PythonCall>,
}

pub struct Channel {
    pub uaid: Uuid,
    pub current_version: u64,
}

impl<T> Client<T>
    where T: Stream<Item = ClientMessage, Error = Error> +
             Sink<SinkItem = ServerMessage, SinkError = Error> +
             'static,
{
    /// Spins up a new client communicating over the websocket `ws` specified.
    ///
    /// The `ws` specified already has ping/pong stuff managed elsewhere, and
    /// this struct is only expected to deal with webpush-specific messages.
    ///
    /// The `tx` provided is a way to communicate with the python thread and
    /// ask it to execute various operations for the tokio thread.
    ///
    /// The `srv` argument is the server that this client is attached to and
    /// the various state behind the server.
    pub fn new(ws: T,
               tx: mpsc::UnboundedSender<PythonCall>,
               srv: &Rc<Server>) -> Client<T> {
        let client = Client::handshake(ws, tx);
        let client = timeout(client, srv.opts.open_handshake_timeout, &srv.handle);

        let srv = srv.clone();
        let work  = client.and_then(move |(ws, client, rx)| {
            let uaid = client.uaid;
            Client::process(client, ws, srv.clone(), rx).then(move |res| {
                srv.disconnet_client(&uaid);
                return res
            })
        });

        Client {
            inner: Box::new(work),
            _marker: marker::PhantomData,
        }
    }

    fn handshake(ws: T, call: mpsc::UnboundedSender<PythonCall>)
        -> MyFuture<(T, ClientState, mpsc::UnboundedReceiver<Notification>)>
    {
        Box::new(ws.into_future().then(move |res| -> MyFuture<_> {
            let (msg, ws) = match res {
                Ok(pair) => pair,
                Err((e, _rx)) => {
                    return Box::new(result(Err(e).chain_err(|| "recv error")))
                }
            };
            let msg = match msg {
                Some(msg) => msg,
                None => return Box::new(err("terminated before handshake".into())),
            };

            let (tx, rx) = mpsc::unbounded();
            let client = match msg {
                ClientMessage::Hello { uaid, channel_ids, use_webpush } => {
                    ClientState {
                        uaid: uaid.unwrap_or_else(Uuid::new_v4),
                        use_webpush: use_webpush.unwrap_or(false),
                        channel_ids: channel_ids.unwrap_or(Vec::new()),
                        tx: tx,
                        call: call,
                    }
                }
                _ => return Box::new(err("non-hello message before handshake".into())),
            };
            let (call, response) = PythonCall::new("verify-hello", client.uaid);
            (&client.call).send(call).expect("python is gone?");
            Box::new(response.and_then(|status| {
                let response = ServerMessage::Hello {
                    uaid: client.uaid,
                    status: status,
                    use_webpush: Some(client.use_webpush),
                };
                ws.send(response).map(|ws| {
                    (ws, client, rx)
                })
            }))
        }))
    }

    fn process(state: ClientState,
               ws: T,
               srv: Rc<Server>,
               rx: mpsc::UnboundedReceiver<Notification>) -> MyFuture<()>
    {
        let uaid = state.uaid;
        srv.connect_client(state);

        let rx = rx.map_err(|_| panic!());
        Box::new(loop_fn((ws, rx), move |(ws, rx)| {
            let srv = srv.clone();
            StreamNext::new(ws, rx).then(move |res| -> MyFuture<_> {
                let (msg, ws, rx) = match res {
                    Ok(None) => return Box::new(ok(Loop::Break(()))),
                    Ok(Some(res)) => res,
                    Err(e) => {
                        return Box::new(result(Err(e).chain_err(|| "recv error")))
                    }
                };

                let response = match msg {
                    Either::A(ClientMessage::Hello { .. }) => {
                        return Box::new(err("double hello received".into()))
                    }

                    Either::A(ClientMessage::Register { channel_id }) => {
                        let status = if srv.register_channel(&uaid, &channel_id) {
                            200
                        } else {
                            409
                        };
                        ServerMessage::Register {
                            status: status,
                            channel_id: channel_id,
                            push_endpoint: format!("http://localhost:8081/{}",
                                                   channel_id),
                        }
                    }

                    Either::A(ClientMessage::Unregister { channel_id }) => {
                        srv.unregister_channel(&uaid, &channel_id);
                        ServerMessage::Unregister {
                            status: 200,
                            channel_id: channel_id,
                        }
                    }

                    // TODO: should handle this?
                    Either::A(ClientMessage::Ack { .. }) => {
                        return Box::new(ok(Loop::Continue((ws, rx))))
                    }

                    Either::B(n) => ServerMessage::Notification(n),
                };
                let ws = ws.send(response);
                Box::new(ws.map(|ws| Loop::Continue((ws, rx))))
            })
        }))
    }
}

impl<T> Future for Client<T>
    where T: Stream<Item = ClientMessage, Error = Error> +
             Sink<SinkItem = ServerMessage, SinkError = Error> +
             'static,
{
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        self.inner.poll()
    }
}

struct StreamNext<S1, S2> {
    left: Option<S1>,
    right: Option<S2>,
}

impl<S1, S2> StreamNext<S1, S2>
    where S1: Stream,
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
    where S1: Stream,
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
        Ok(Async::Ready(Some((item,
                              self.left.take().unwrap(),
                              self.right.take().unwrap()))))
    }
}
