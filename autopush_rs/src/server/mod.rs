use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::net::{IpAddr, ToSocketAddrs};
use std::panic;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use futures::sync::oneshot;
use futures::task::{self, Task};
use futures::{Stream, Future, Sink, Async, Poll, AsyncSink, StartSend};
use libc::c_char;
use serde_json;
use time;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Core, Timeout, Handle, Interval};
use tokio_io;
use tokio_tungstenite::{accept_async, WebSocketStream};
use tungstenite::Message;
use uuid::Uuid;

use client::{Client, RegisteredClient};
use errors::*;
use protocol::{ClientMessage, ServerMessage, ServerNotification, Notification};
use queue::{self, AutopushQueue};
use rt::{self, AutopushError, UnwindGuard};
use server::webpush_io::WebpushIo;
use server::dispatch::{Dispatch, RequestType};
use util::{self, RcObject, timeout};

mod dispatch;
mod webpush_io;

#[repr(C)]
pub struct AutopushServer {
    inner: UnwindGuard<AutopushServerInner>,
}

struct AutopushServerInner {
    opts: Arc<ServerOptions>,
    // Used when shutting down a server
    tx: Cell<Option<oneshot::Sender<()>>>,
    thread: Cell<Option<thread::JoinHandle<()>>>,
}

#[repr(C)]
pub struct AutopushServerOptions {
    pub debug: i32,
    pub router_ip: *const c_char,
    pub host_ip: *const c_char,
    pub router_port: u16,
    pub port: u16,
    pub url: *const c_char,
    pub ssl_key: *const c_char,
    pub ssl_cert: *const c_char,
    pub ssl_dh_param: *const c_char,
    pub open_handshake_timeout: u32,
    pub auto_ping_interval: f64,
    pub auto_ping_timeout: f64,
    pub max_connections: u32,
    pub close_handshake_timeout: u32,
    pub json_logging: i32,
}

pub struct Server {
    uaids: RefCell<HashMap<Uuid, RegisteredClient>>,
    open_connections: Cell<u32>,
    pub tx: queue::Sender,
    pub opts: Arc<ServerOptions>,
    pub handle: Handle,
}

pub struct ServerOptions {
    pub debug: bool,
    pub host_ip: String,
    pub router_ip: String,
    pub router_port: u16,
    pub port: u16,
    pub url: String,
    pub ssl_key: Option<PathBuf>,
    pub ssl_cert: Option<PathBuf>,
    pub ssl_dh_param: Option<PathBuf>,
    pub open_handshake_timeout: Option<Duration>,
    pub auto_ping_interval: Duration,
    pub auto_ping_timeout: Duration,
    pub max_connections: Option<u32>,
    pub close_handshake_timeout: Option<Duration>,
}

fn resolve(host: &str) -> IpAddr {
    (host, 0).to_socket_addrs().unwrap().next().unwrap().ip()
}

#[no_mangle]
pub extern "C" fn autopush_server_new(opts: *const AutopushServerOptions,
                                      err: &mut AutopushError)
    -> *mut AutopushServer
{
    unsafe fn to_s<'a>(ptr: *const c_char) -> Option<&'a str> {
        if ptr.is_null() {
            return None
        }
        let s = CStr::from_ptr(ptr).to_str().expect("invalid utf-8");
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    unsafe fn ito_dur(seconds: u32) -> Option<Duration> {
        if seconds == 0 {
            None
        } else {
            Some(Duration::new(seconds.into(), 0))
        }
    }

    unsafe fn fto_dur(seconds: f64) -> Option<Duration> {
        if seconds == 0.0 {
            None
        } else {
            Some(Duration::new(seconds as u64,
                               (seconds.fract() * 1_000_000_000.0) as u32))
        }
    }

    rt::catch(err, || unsafe {
        let opts = &*opts;

        util::init_logging(opts.json_logging != 0);

        let opts = ServerOptions {
            debug: opts.debug != 0,
            host_ip: to_s(opts.host_ip).expect("hostname must be specified").to_string(),
            router_ip: to_s(opts.router_ip).expect("router hostname must be specified").to_string(),
            port: opts.port,
            router_port: opts.router_port,
            url: to_s(opts.url).expect("url must be specified").to_string(),
            ssl_key: to_s(opts.ssl_key).map(PathBuf::from),
            ssl_cert: to_s(opts.ssl_cert).map(PathBuf::from),
            ssl_dh_param: to_s(opts.ssl_dh_param).map(PathBuf::from),
            auto_ping_interval: fto_dur(opts.auto_ping_interval)
                .expect("ping interval cannot be 0"),
            auto_ping_timeout: fto_dur(opts.auto_ping_timeout)
                .expect("ping timeout cannot be 0"),
            close_handshake_timeout: ito_dur(opts.close_handshake_timeout),
            max_connections: if opts.max_connections == 0 {
                None
            } else {
                Some(opts.max_connections)
            },
            open_handshake_timeout: ito_dur(opts.open_handshake_timeout),
        };

        Box::new(AutopushServer {
            inner: UnwindGuard::new(AutopushServerInner {
                opts: Arc::new(opts),
                tx: Cell::new(None),
                thread: Cell::new(None),
            }),
        })
    })
}

#[no_mangle]
pub extern "C" fn autopush_server_start(srv: *mut AutopushServer,
                                        queue: *mut AutopushQueue,
                                        err: &mut AutopushError) -> i32 {
    unsafe {
        (*srv).inner.catch(err, |srv| {
            let tx = (*queue).tx();
            let (tx, thread) = Server::start(&srv.opts, tx)
                .expect("failed to start server");
            srv.tx.set(Some(tx));
            srv.thread.set(Some(thread));
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_server_stop(srv: *mut AutopushServer,
                                       err: &mut AutopushError) -> i32 {
    unsafe {
        (*srv).inner.catch(err, |srv| {
            srv.stop().expect("tokio thread panicked");
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_server_free(srv: *mut AutopushServer) {
    rt::abort_on_panic(|| unsafe {
        Box::from_raw(srv);
    })
}

impl AutopushServerInner {
    /// Blocks execution of the calling thread until the helper thread with the
    /// tokio reactor has exited.
    fn stop(&self) -> Result<()> {
        drop(self.tx.take());
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(ErrorKind::Thread)?;
        }
        Ok(())
    }
}

impl Drop for AutopushServerInner {
    fn drop(&mut self) {
        drop(self.stop());
    }
}

impl Server {
    /// Creates a new server handle to send to python.
    ///
    /// This will spawn a new server with the `opts` specified, spinning up a
    /// separate thread for the tokio reactor. The returned
    /// `AutopushServerInner` is a handle to the spawned thread and can be used
    /// to interact with it (e.g. shut it down).
    fn start(opts: &Arc<ServerOptions>, tx: queue::Sender)
        -> io::Result<(oneshot::Sender<()>, thread::JoinHandle<()>)>
    {
        let (donetx, donerx) = oneshot::channel();
        let (inittx, initrx) = oneshot::channel();

        let opts = opts.clone();
        assert!(opts.ssl_key.is_none(), "ssl not supported");
        assert!(opts.ssl_cert.is_none(), "ssl not supported");
        assert!(opts.ssl_dh_param.is_none(), "ssl not supported");

        let thread = thread::spawn(move || {
            let (srv, mut core) = match Server::new(&opts, tx) {
                Ok(core) => {
                    inittx.send(None).unwrap();
                    core
                }
                Err(e) => return inittx.send(Some(e)).unwrap(),
            };

            // For now during development spin up a dummy HTTP server which is
            // used to send notifications to clients.
            {
                use hyper::server::Http;

                let handle = core.handle();
                let router_ip = resolve(&srv.opts.router_ip);
                let addr = format!("{}:{}", router_ip, srv.opts.router_port).parse().unwrap();
                let push_listener = TcpListener::bind(&addr, &handle).unwrap();
                let proto = Http::new();
                let push_srv = push_listener.incoming().for_each(move |(socket, addr)| {
                    proto.bind_connection(&handle, socket, addr,
                                          ::http::Push(srv.clone()));
                    Ok(())
                });
                core.handle().spawn(push_srv.then(|res| {
                    info!("Http server {:?}", res);
                    Ok(())
                }));
            }

            drop(core.run(donerx));
        });

        match initrx.wait() {
            Ok(Some(e)) => Err(e),
            Ok(None) => Ok((donetx, thread)),
            Err(_) => panic::resume_unwind(thread.join().unwrap_err()),
        }
    }

    fn new(opts: &Arc<ServerOptions>, tx: queue::Sender)
        -> io::Result<(Rc<Server>, Core)>
    {
        let core = Core::new()?;
        let srv = Rc::new(Server {
            opts: opts.clone(),
            uaids: RefCell::new(HashMap::new()),
            open_connections: Cell::new(0),
            handle: core.handle(),
            tx: tx,
        });
        let host_ip = resolve(&srv.opts.host_ip);
        let addr = format!("{}:{}", host_ip, srv.opts.port);
        let ws_listener = TcpListener::bind(&addr.parse().unwrap(), &srv.handle)?;

        assert!(srv.opts.ssl_key.is_none(), "ssl not supported yet");
        assert!(srv.opts.ssl_cert.is_none(), "ssl not supported yet");
        assert!(srv.opts.ssl_dh_param.is_none(), "ssl not supported yet");

        let handle = core.handle();
        let srv2 = srv.clone();
        let ws_srv = ws_listener.incoming()
            .map_err(|e| Error::from(e))

            .for_each(move |(socket, addr)| {
                // Make sure we're not handling too many clients before we start the
                // websocket handshake.
                let max = srv.opts.max_connections.unwrap_or(u32::max_value());
                if srv.open_connections.get() >= max {
                    info!("dropping {} as we already have too many open \
                           connections", addr);
                    return Ok(())
                }
                srv.open_connections.set(srv.open_connections.get() + 1);

                // TODO: TCP socket options here?

                // Figure out if this is a websocket or a `/status` request,
                // without letting it take too long.
                let request = Dispatch::new(socket);
                let request = timeout(request,
                                      srv.opts.open_handshake_timeout,
                                      &handle);
                let srv2 = srv.clone();
                let handle2 = handle.clone();
                let client = request.and_then(move |(socket, request)| -> MyFuture<_> {
                    match request {
                        RequestType::Status => write_status(socket),
                        RequestType::Websocket => {
                            // Perform the websocket handshake on each
                            // connection, but don't let it take too long.
                            let ws = accept_async(socket, None).chain_err(|| {
                                "failed to accept client"
                            });
                            let ws = timeout(ws,
                                             srv2.opts.open_handshake_timeout,
                                             &handle2);

                            // Once the handshake is done we'll start the main
                            // communication with the client, managing pings
                            // here and deferring to `Client` to start driving
                            // the internal state machine.
                            Box::new(ws.and_then(move |ws| {
                                PingManager::new(&srv2, ws)
                                    .chain_err(|| "failed to make ping handler")
                            }).flatten())
                        }
                    }
                });

                let srv = srv.clone();
                handle.spawn(client.then(move |res| {
                    srv.open_connections.set(srv.open_connections.get() - 1);
                    if let Err(e) = res {
                        let mut error = e.to_string();
                        for err in e.iter().skip(1) {
                            error.push_str("\n");
                            error.push_str(&err.to_string());
                        }
                        error!("{}: {}", addr, error);
                    }
                    Ok(())
                }));

                Ok(())
            });

        core.handle().spawn(ws_srv.then(|res| {
            debug!("srv res: {:?}", res.map(drop));
            Ok(())
        }));

        Ok((srv2, core))
    }

    /// Informs this server that a new `client` has connected
    ///
    /// For now just registers internal state by keeping track of the `client`,
    /// namely its channel to send notifications back.
    pub fn connect_client(&self, client: RegisteredClient) {
        debug!("Connecting a client!");
        assert!(self.uaids.borrow_mut().insert(client.uaid, client).is_none());
    }

    /// A notification has come for the uaid
    pub fn notify_client(&self, uaid: Uuid, notif: Notification) -> Result<()> {
        let mut uaids = self.uaids.borrow_mut();
        if let Some(client) = uaids.get_mut(&uaid) {
            debug!("Found a client to deliver a notification to");
            // TODO: Don't unwrap, handle error properly
            (&client.tx).send(ServerNotification::Notification(notif)).unwrap();
            info!("Dropped notification in queue");
            return Ok(());
        }
        Err("User not connected".into())
    }

    /// The client specified by `uaid` has disconnected.
    pub fn disconnet_client(&self, uaid: &Uuid) {
        debug!("Disconnecting client!");
        let mut uaids = self.uaids.borrow_mut();
        uaids.remove(uaid).expect("uaid not registered");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // we're done sending messages, close out the queue
        drop(self.tx.send(None));
    }
}

struct PingManager {
    socket: RcObject<WebpushSocket<WebSocketStream<WebpushIo>>>,
    ping_interval: Interval,
    timeout: TimeoutState,
    srv: Rc<Server>,
    client: CloseState<Client<RcObject<WebpushSocket<WebSocketStream<WebpushIo>>>>>,
}

enum TimeoutState {
    None,
    Ping(Timeout),
    Close(Timeout),
}

enum CloseState<T> {
    Exchange(T),
    Closing,
}

impl PingManager {
    fn new(srv: &Rc<Server>, socket: WebSocketStream<WebpushIo>)
        -> io::Result<PingManager>
    {
        // The `socket` is itself a sink and a stream, and we've also got a sink
        // (`tx`) and a stream (`rx`) to send messages. Half of our job will be
        // doing all this proxying: reading messages from `socket` and sending
        // them to `tx` while also reading messages from `rx` and sending them
        // on `socket`.
        //
        // Our other job will be to manage the websocket protocol pings going
        // out and coming back. The `opts` provided indicate how often we send
        // pings and how long we'll wait for the ping to come back before we
        // time it out.
        //
        // To make these tasks easier we start out by throwing the `socket` into
        // an `Rc` object. This'll allow us to share it between the ping/pong
        // management and message shuffling.
        let socket = RcObject::new(WebpushSocket::new(socket));
        Ok(PingManager {
            ping_interval: Interval::new(srv.opts.auto_ping_interval, &srv.handle)?,
            timeout: TimeoutState::None,
            socket: socket.clone(),
            client: CloseState::Exchange(Client::new(socket, srv)),
            srv: srv.clone(),
        })
    }
}

impl Future for PingManager {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        // If it's time for us to send a ping, then queue up a ping to get sent
        // and start the clock for that ping to time out once the ping is
        // actually sent out on the socket.
        while let Async::Ready(_) = self.ping_interval.poll()? {
            match self.timeout {
                TimeoutState::None => {}
                _ => continue,
            }
            debug!("scheduling a ping to be sent");
            self.socket.borrow_mut().ping = true;
        }
        {
            let mut socket = self.socket.borrow_mut();
            if socket.ping && socket.send_ping()?.is_ready() {
                let timeout = Timeout::new(self.srv.opts.auto_ping_timeout,
                                           &self.srv.handle)?;
                self.timeout = TimeoutState::Ping(timeout);
            }
        }

        // If the client takes too long to respond to our websocket ping or too
        // long to execute the closing handshake then we terminate the whole
        // connection.
        match self.timeout {
            TimeoutState::None => {}
            TimeoutState::Close(ref mut timeout) => {
                if timeout.poll()?.is_ready() {
                    if let CloseState::Exchange(ref mut client) = self.client {
                        client.shutdown();
                    }
                    return Err("close handshake took too long".into())
                }
            }
            TimeoutState::Ping(ref mut timeout) => {
                if timeout.poll()?.is_ready() {
                    // We may not actually be reading messages from the
                    // websocket right now, could have been waiting on something
                    // else. Instead of immediately returning an error here wait
                    // for the stream to return `NotReady` when looking for
                    // messages, as then we're extra sure that no pong was
                    // received after this timeout elapsed.
                    debug!("ping timeout fired, scheduling error to maybe happen");
                    self.socket.borrow_mut().pong_timeout = true;
                    // `timeout` is cleared in the clause below
                }
            }
        }

        // Received pongs will clear our ping timeout, but not the close
        // timeout.
        if let TimeoutState::Ping(_) = self.timeout {
            let mut socket = self.socket.borrow_mut();
            if socket.poll_pong().is_ready() || socket.pong_timeout {
                debug!("clearing ping timeout");
                self.timeout = TimeoutState::None;
            }
        }

        // Be sure to always flush out any buffered messages/pings
        self.socket.borrow_mut().poll_complete().chain_err(|| {
            "failed routine `poll_complete` call"
        })?;

        // At this point looks our state of ping management A-OK, so try to
        // make progress on our client, and when done with that execute the
        // closing handshake.
        loop {
            match self.client {
                CloseState::Exchange(ref mut client) => try_ready!(client.poll()),
                CloseState::Closing => return Ok(self.socket.close()?),
            }

            self.client = CloseState::Closing;
            if let Some(dur) = self.srv.opts.close_handshake_timeout {
                let timeout = Timeout::new(dur, &self.srv.handle)?;
                self.timeout = TimeoutState::Close(timeout);
            }
        }
    }
}

// Wrapper struct to take a Sink/Stream of `Message` to a Sink/Stream of
// `ClientMessage` and `ServerMessage`.
struct WebpushSocket<T> {
    inner: T,
    pong: Pong,
    ping: bool,
    pong_timeout: bool,
}

enum Pong {
    None,
    Received,
    Waiting(Task),
}

impl<T> WebpushSocket<T> {
    fn new(t: T) -> WebpushSocket<T> {
        WebpushSocket {
            inner: t,
            pong: Pong::None,
            ping: false,
            pong_timeout: false,
        }
    }

    fn poll_pong(&mut self) -> Async<()> {
        match mem::replace(&mut self.pong, Pong::None) {
            Pong::None => {}
            Pong::Received => return Async::Ready(()),
            Pong::Waiting(_) => {}
        }
        debug!("waiting for a pong");
        self.pong = Pong::Waiting(task::current());
        Async::NotReady
    }

    fn send_ping(&mut self) -> Poll<(), Error>
        where T: Sink<SinkItem = Message>, Error: From<T::SinkError>
    {
        if self.ping {
            debug!("sending a ping");
            match self.inner.start_send(Message::Ping(Vec::new()))? {
                AsyncSink::Ready => {
                    debug!("ping sent");
                    self.ping = false;
                }
                AsyncSink::NotReady(_) => {
                    debug!("ping not ready to be sent");
                    return Ok(Async::NotReady)
                }
            }
        }
        Ok(Async::Ready(()))
    }
}

impl<T> Stream for WebpushSocket<T>
    where T: Stream<Item = Message>,
          Error: From<T::Error>,
{
    type Item = ClientMessage;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<ClientMessage>, Error> {
        loop {
            let msg = match self.inner.poll()? {
                Async::Ready(Some(msg)) => msg,
                Async::Ready(None) => return Ok(None.into()),
                Async::NotReady => {
                    // If we don't have any more messages and our pong timeout
                    // elapsed (set above) then this is where we start
                    // triggering errors.
                    if self.pong_timeout {
                        return Err("failed to receive a pong in time".into())
                    }
                    return Ok(Async::NotReady)
                }
            };
            match msg {
                Message::Text(ref s) => {
                    trace!("text message {}", s);
                    let msg = serde_json::from_str(s).chain_err(|| "invalid json text")?;
                    return Ok(Some(msg).into())
                }

                Message::Binary(_) => {
                    return Err("binary messages not accepted".into())
                }

                // sending a pong is already managed by lower layers, just go to
                // the next message
                Message::Ping(_) => {}

                // Wake up tasks waiting for a pong, if any.
                Message::Pong(_) => {
                    self.pong_timeout = false;
                    match mem::replace(&mut self.pong, Pong::Received) {
                        Pong::None => {}
                        Pong::Received => {}
                        Pong::Waiting(task) => {
                            debug!("notifying a task of a pong");
                            task.notify();
                        }
                    }
                }
            }
        }
    }
}

impl<T> Sink for WebpushSocket<T>
    where T: Sink<SinkItem = Message>,
          Error: From<T::SinkError>,
{
    type SinkItem = ServerMessage;
    type SinkError = Error;

    fn start_send(&mut self, msg: ServerMessage)
        -> StartSend<ServerMessage, Error>
    {
        if self.send_ping()?.is_not_ready() {
            return Ok(AsyncSink::NotReady(msg))
        }
        let s = serde_json::to_string(&msg).chain_err(|| "failed to serialize")?;
        match self.inner.start_send(Message::Text(s))? {
            AsyncSink::Ready => Ok(AsyncSink::Ready),
            AsyncSink::NotReady(_) => Ok(AsyncSink::NotReady(msg)),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Error> {
        try_ready!(self.send_ping());
        Ok(self.inner.poll_complete()?)
    }

    fn close(&mut self) -> Poll<(), Error> {
        try_ready!(self.poll_complete());
        Ok(self.inner.close()?)
    }
}

fn write_status(socket: WebpushIo) -> MyFuture<()> {
    let data = json!({
        "status": "OK",
        "version": env!("CARGO_PKG_VERSION"),
    }).to_string();
    let data = format!("\
        HTTP/1.1 200 Ok\r\n\
        Server: webpush\r\n\
        Date: {date}\r\n\
        Content-Length: {len}\r\n\
        \r\n\
        {data}\
    ",
        date = time::at(time::get_time()).rfc822(),
        len = data.len(),
        data = data,
    );
    Box::new(tokio_io::io::write_all(socket, data.into_bytes())
        .map(|_| ())
        .chain_err(|| "failed to write status response"))
}
