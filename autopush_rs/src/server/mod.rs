use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::panic;
use std::panic::PanicInfo;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::thread;
use std::time::{Instant, Duration};

use cadence::StatsdClient;
use futures;
use futures::sync::oneshot;
use futures::task;
use futures::{Stream, Future, Sink, Async, Poll, AsyncSink, StartSend};
use hyper;
use hyper::server::Http;
use libc::c_char;
use openssl::ssl::SslAcceptor;
use sentry;
use serde_json;
use time;
use tokio_core::net::TcpListener;
use tokio_core::reactor::{Core, Timeout, Handle};
use tokio_io;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tungstenite::handshake::server::Request;
use tungstenite::Message;
use uuid::Uuid;

use client::{Client, RegisteredClient};
use errors::*;
use errors::{Error, Result};
use http;
use protocol::{ClientMessage, ServerMessage, ServerNotification, Notification};
use queue::{self, AutopushQueue};
use rt::{self, AutopushError, UnwindGuard};
use server::dispatch::{Dispatch, RequestType};
use server::metrics::metrics_from_opts;
use server::webpush_io::WebpushIo;
use util::{self, RcObject, timeout};

mod dispatch;
mod metrics;
mod tls;
mod webpush_io;

const UAHEADER: &str = "User-Agent";

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
    pub statsd_host: *const c_char,
    pub statsd_port: u16,
}

pub struct Server {
    uaids: RefCell<HashMap<Uuid, RegisteredClient>>,
    open_connections: Cell<u32>,
    tls_acceptor: Option<SslAcceptor>,
    pub tx: queue::Sender,
    pub opts: Arc<ServerOptions>,
    pub handle: Handle,
    pub metrics: StatsdClient,
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
    pub statsd_host: Option<String>,
    pub statsd_port: u16,
    pub logger: util::LogGuards,
}

/// Resolve a hostname into a SocketAddr with a specific port
fn resolve_with_port(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port).to_socket_addrs()?.next().ok_or(Error::from("invalid host/port"))
}

#[no_mangle]
pub extern "C" fn autopush_server_new(
    opts: *const AutopushServerOptions,
    err: &mut AutopushError,
) -> *mut AutopushServer {
    unsafe fn to_s<'a>(ptr: *const c_char) -> Option<&'a str> {
        if ptr.is_null() {
            return None;
        }
        let s = CStr::from_ptr(ptr).to_str().expect("invalid utf-8");
        if s.is_empty() { None } else { Some(s) }
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
            Some(Duration::new(
                seconds as u64,
                (seconds.fract() * 1_000_000_000.0) as u32,
            ))
        }
    }

    rt::catch(err, || unsafe {
        let opts = &*opts;

        let hostname = to_s(opts.host_ip)
            .expect("hostname must be specified")
            .as_ref();

        let logger = util::init_logging(opts.json_logging != 0, hostname);
        let opts = ServerOptions {
            debug: opts.debug != 0,
            host_ip: to_s(opts.host_ip)
                .expect("hostname must be specified")
                .to_string(),
            router_ip: to_s(opts.router_ip)
                .expect("router hostname must be specified")
                .to_string(),
            port: opts.port,
            router_port: opts.router_port,
            statsd_host: to_s(opts.statsd_host).map(|s| s.to_string()),
            statsd_port: opts.statsd_port,
            url: to_s(opts.url).expect("url must be specified").to_string(),
            ssl_key: to_s(opts.ssl_key).map(PathBuf::from),
            ssl_cert: to_s(opts.ssl_cert).map(PathBuf::from),
            ssl_dh_param: to_s(opts.ssl_dh_param).map(PathBuf::from),
            auto_ping_interval: fto_dur(opts.auto_ping_interval).expect(
                "ping interval cannot be 0",
            ),
            auto_ping_timeout: fto_dur(opts.auto_ping_timeout).expect("ping timeout cannot be 0"),
            close_handshake_timeout: ito_dur(opts.close_handshake_timeout),
            max_connections: if opts.max_connections == 0 {
                None
            } else {
                Some(opts.max_connections)
            },
            open_handshake_timeout: ito_dur(opts.open_handshake_timeout),
            logger: logger,
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
pub extern "C" fn autopush_server_start(
    srv: *mut AutopushServer,
    queue: *mut AutopushQueue,
    err: &mut AutopushError,
) -> i32 {
    unsafe {
        (*srv).inner.catch(err, |srv| {
            let tx = (*queue).tx();
            let (tx, thread) = Server::start(&srv.opts, tx).expect("failed to start server");
            srv.tx.set(Some(tx));
            srv.thread.set(Some(thread));
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_server_stop(srv: *mut AutopushServer, err: &mut AutopushError) -> i32 {
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
    fn start(
        opts: &Arc<ServerOptions>,
        tx: queue::Sender,
    ) -> Result<(oneshot::Sender<()>, thread::JoinHandle<()>)> {
        let (donetx, donerx) = oneshot::channel();
        let (inittx, initrx) = oneshot::channel();

        let opts = opts.clone();
        let thread = thread::spawn(move || {
            let (srv, mut core) = match Server::new(&opts, tx) {
                Ok(core) => {
                    inittx.send(None).unwrap();
                    core
                }
                Err(e) => return inittx.send(Some(e)).unwrap(),
            };

            // Internal HTTP server setup
            {
                let handle = core.handle();
                let addr = resolve_with_port(&srv.opts.router_ip, srv.opts.router_port)
                    .expect("Invalid router_ip/port");
                let push_listener = TcpListener::bind(&addr, &handle).unwrap();
                let http = Http::<hyper::Chunk>::new();
                let push_srv = push_listener.incoming().for_each(move |(socket, _)| {
                    handle.spawn(
                        http
                            .serve_connection(socket, http::Push(srv.clone()))
                            .map(|_| ())
                            .map_err(|e| debug!("Http server connection error: {}", e)),
                    );
                    Ok(())
                });
                core.handle().spawn(push_srv.then(|res| {
                    debug!("Http server {:?}", res);
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

    fn new(opts: &Arc<ServerOptions>, tx: queue::Sender) -> Result<(Rc<Server>, Core)> {
        // Setup Sentry logging if a SENTRY_DSN exists
        let sentry_dsn_option = option_env!("SENTRY_DSN");
        if let Some(sentry_dsn) = sentry_dsn_option {
            // Spin up a new thread with a new reactor core for the sentry handler
            thread::spawn(move || {
                let creds = sentry_dsn
                    .parse::<sentry::SentryCredential>()
                    .expect("Invalid Sentry DSN specified");
                let mut core = Core::new().expect("Unable to create core");
                let sentry = sentry::Sentry::from_settings(core.handle(), Default::default(), creds);
                // Get the prior panic hook
                let hook = panic::take_hook();
                sentry.register_panic_handler(Some(move |info: &PanicInfo| -> () {
                    hook(info);
                }));
                core.run(futures::empty::<(), ()>()).expect("Error starting sentry thread");
            });
        }

        let core = Core::new()?;
        let srv = Rc::new(Server {
            opts: opts.clone(),
            uaids: RefCell::new(HashMap::new()),
            open_connections: Cell::new(0),
            handle: core.handle(),
            tx: tx,
            tls_acceptor: tls::configure(opts),
            metrics: metrics_from_opts(opts)?,
        });
        let addr = resolve_with_port(&srv.opts.host_ip, srv.opts.port)
            .expect("Invalid host_ip/port");
        let ws_listener = TcpListener::bind(&addr, &srv.handle)?;

        let handle = core.handle();
        let srv2 = srv.clone();
        let ws_srv = ws_listener
            .incoming()
            .map_err(|e| Error::from(e))
            .for_each(move |(socket, addr)| {
                // Make sure we're not handling too many clients before we start the
                // websocket handshake.
                let max = srv.opts.max_connections.unwrap_or(u32::max_value());
                if srv.open_connections.get() >= max {
                    info!(
                        "dropping {} as we already have too many open \
                           connections",
                        addr
                    );
                    return Ok(());
                }
                srv.open_connections.set(srv.open_connections.get() + 1);

                // TODO: TCP socket options here?

                // Process TLS (if configured)
                let socket = tls::accept(&srv, socket);

                // Figure out if this is a websocket or a `/status` request,
                let request = socket.and_then(Dispatch::new);

                // Time out both the TLS accept (if any) along with the dispatch
                // to figure out where we're going.
                let request = timeout(request, srv.opts.open_handshake_timeout, &handle);
                let srv2 = srv.clone();
                let handle2 = handle.clone();

                let host = format!("{}", addr.ip());

                // Setup oneshot to extract the user-agent from the header callback
                let (uatx, uarx) = oneshot::channel();
                let callback = |req: &Request| {
                    if let Some(value) = req.headers.find_first(UAHEADER) {
                        let mut valstr = String::new();
                        for c in value.iter() {
                            let c = *c as char;
                            valstr.push(c);
                        }
                        debug!("Found user-agent string"; "user-agent" => valstr.as_str());
                        uatx.send(valstr).unwrap();
                    }
                    debug!("No agent string found");
                    Ok(None)
                };

                let client = request.and_then(move |(socket, request)| -> MyFuture<_> {
                    match request {
                        RequestType::Status => write_status(socket),
                        RequestType::Websocket => {
                            // Perform the websocket handshake on each
                            // connection, but don't let it take too long.
                            let ws = accept_hdr_async(socket, callback).chain_err(|| "failed to accept client");
                            let ws = timeout(ws, srv2.opts.open_handshake_timeout, &handle2);

                            // Once the handshake is done we'll start the main
                            // communication with the client, managing pings
                            // here and deferring to `Client` to start driving
                            // the internal state machine.
                            Box::new(
                                ws.and_then(move |ws| {
                                    PingManager::new(&srv2, ws, uarx, host).chain_err(
                                        || "failed to make ping handler",
                                    )
                                }).flatten(),
                            )
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
                        debug!("{}: {}", addr, error);
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
        assert!(
            self.uaids
                .borrow_mut()
                .insert(client.uaid, client)
                .is_none()
        );
    }

    /// A notification has come for the uaid
    pub fn notify_client(&self, uaid: Uuid, notif: Notification) -> Result<()> {
        let uaids = self.uaids.borrow();
        if let Some(client) = uaids.get(&uaid) {
            debug!("Found a client to deliver a notification to");
            let result = client
                .tx
                .unbounded_send(ServerNotification::Notification(notif));
            if result.is_ok() {
                debug!("Dropped notification in queue");
                return Ok(());
            }
        }
        Err("User not connected".into())
    }

    /// A check for notification command has come for the uaid
    pub fn check_client_storage(&self, uaid: Uuid) -> Result<()> {
        let uaids = self.uaids.borrow();
        if let Some(client) = uaids.get(&uaid) {
            let result = client
                .tx
                .unbounded_send(ServerNotification::CheckStorage);
            if result.is_ok() {
                debug!("Told client to check storage");
                return Ok(());
            }
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
    timeout: Timeout,
    waiting: WaitingFor,
    srv: Rc<Server>,
    client: CloseState<Client<RcObject<WebpushSocket<WebSocketStream<WebpushIo>>>>>,
}

enum WaitingFor {
    SendPing,
    Pong,
    Close,
}

enum CloseState<T> {
    Exchange(T),
    Closing,
}

impl PingManager {
    fn new(
        srv: &Rc<Server>,
        socket: WebSocketStream<WebpushIo>,
        uarx: oneshot::Receiver<String>,
        host: String)
        -> io::Result<PingManager> {
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
            timeout: Timeout::new(srv.opts.auto_ping_interval, &srv.handle)?,
            waiting: WaitingFor::SendPing,
            socket: socket.clone(),
            client: CloseState::Exchange(Client::new(socket, srv, uarx, host)),
            srv: srv.clone(),
        })
    }
}

impl Future for PingManager {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        let mut socket = self.socket.borrow_mut();
        loop {
            if socket.ping {
                if socket.send_ping()?.is_ready() {
                    let at = Instant::now() + self.srv.opts.auto_ping_timeout;
                    self.timeout.reset(at);
                    self.waiting = WaitingFor::Pong;
                } else {
                    break;
                }
            }
            assert!(!socket.ping);
            match self.waiting {
                WaitingFor::SendPing => {
                    assert!(!socket.pong_timeout);
                    assert!(!socket.pong_received);
                    match self.timeout.poll()? {
                        Async::Ready(()) => {
                            debug!("scheduling a ping to get sent");
                            socket.ping = true;
                        }
                        Async::NotReady => break,
                    }
                }
                WaitingFor::Pong => {
                    if socket.pong_received {
                        // If we received a pong, then switch us back to waiting
                        // to send out a ping
                        debug!("pong received, going back to sending a ping");
                        assert!(!socket.pong_timeout);
                        let at = Instant::now() + self.srv.opts.auto_ping_interval;
                        self.timeout.reset(at);
                        self.waiting = WaitingFor::SendPing;
                        socket.pong_received = false;
                    } else if socket.pong_timeout {
                        // If our socket is waiting to deliver a pong timeout,
                        // then no need to keep checking the timer and we can
                        // keep going
                        debug!("waiting for socket to see pong timed out");
                        break;
                    } else if self.timeout.poll()?.is_ready() {
                        // We may not actually be reading messages from the
                        // websocket right now, could have been waiting on
                        // something else. Instead of immediately returning an
                        // error here wait for the stream to return `NotReady`
                        // when looking for messages, as then we're extra sure
                        // that no pong was received after this timeout elapsed.
                        debug!("waited too long for a pong");
                        socket.pong_timeout = true;
                    } else {
                        break;
                    }
                }
                WaitingFor::Close => {
                    assert!(!socket.pong_timeout);
                    if self.timeout.poll()?.is_ready() {
                        if let CloseState::Exchange(ref mut client) = self.client {
                            client.shutdown();
                        }
                        // So did the shutdown not work? We must call shutdown but no client here?
                        return Err("close handshake took too long".into());
                    }
                }
            }
        }

        // Be sure to always flush out any buffered messages/pings
        socket.poll_complete().chain_err(
            || "failed routine `poll_complete` call",
        )?;
        drop(socket);

        // At this point looks our state of ping management A-OK, so try to
        // make progress on our client, and when done with that execute the
        // closing handshake.
        loop {
            match self.client {
                CloseState::Exchange(ref mut client) => try_ready!(client.poll()),
                CloseState::Closing => return Ok(self.socket.borrow_mut().close()?),
            }

            self.client = CloseState::Closing;
            if let Some(dur) = self.srv.opts.close_handshake_timeout {
                let at = Instant::now() + dur;
                self.timeout.reset(at);
                self.waiting = WaitingFor::Close;
            }
        }
    }
}

// Wrapper struct to take a Sink/Stream of `Message` to a Sink/Stream of
// `ClientMessage` and `ServerMessage`.
struct WebpushSocket<T> {
    inner: T,
    pong_received: bool,
    ping: bool,
    pong_timeout: bool,
}

impl<T> WebpushSocket<T> {
    fn new(t: T) -> WebpushSocket<T> {
        WebpushSocket {
            inner: t,
            pong_received: false,
            ping: false,
            pong_timeout: false,
        }
    }

    fn send_ping(&mut self) -> Poll<(), Error>
    where
        T: Sink<SinkItem = Message>,
        Error: From<T::SinkError>,
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
                    return Ok(Async::NotReady);
                }
            }
        }
        Ok(Async::Ready(()))
    }
}

impl<T> Stream for WebpushSocket<T>
where
    T: Stream<Item = Message>,
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
                        return Err("failed to receive a pong in time".into());
                    }
                    return Ok(Async::NotReady);
                }
            };
            match msg {
                Message::Text(ref s) => {
                    trace!("text message {}", s);
                    let msg = serde_json::from_str(s).chain_err(|| "invalid json text")?;
                    return Ok(Some(msg).into());
                }

                Message::Binary(_) => return Err("binary messages not accepted".into()),

                // sending a pong is already managed by lower layers, just go to
                // the next message
                Message::Ping(_) => {}

                // Wake up ourselves to ensure the above ping logic eventually
                // sees this pong.
                Message::Pong(_) => {
                    self.pong_received = true;
                    self.pong_timeout = false;
                    task::current().notify();
                }
            }
        }
    }
}

impl<T> Sink for WebpushSocket<T>
where
    T: Sink<SinkItem = Message>,
    Error: From<T::SinkError>,
{
    type SinkItem = ServerMessage;
    type SinkError = Error;

    fn start_send(&mut self, msg: ServerMessage) -> StartSend<ServerMessage, Error> {
        if self.send_ping()?.is_not_ready() {
            return Ok(AsyncSink::NotReady(msg));
        }
        let s = serde_json::to_string(&msg).chain_err(
            || "failed to serialize",
        )?;
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
    Box::new(
        tokio_io::io::write_all(socket, data.into_bytes())
            .map(|_| ())
            .chain_err(|| "failed to write status response"),
    )
}
