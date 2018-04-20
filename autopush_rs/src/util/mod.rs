//! Various small utilities accumulated over time for the WebPush server
use std::io;
use std::time::Duration;

use hostname::get_hostname;
use futures::future::{Either, Future, IntoFuture};
use slog;
use slog_async;
use slog_term;
use slog_scope;
use slog_stdlog;
use slog::Drain;
use tokio_core::reactor::{Handle, Timeout};

use errors::*;

mod autojson;
mod aws;
pub mod megaphone;
#[macro_use]
pub mod ddb_helpers;
mod rc;
mod send_all;
mod user_agent;

use self::aws::get_ec2_instance_id;
pub use self::send_all::MySendAll;
pub use self::rc::RcObject;
pub use self::user_agent::parse_user_agent;

/// Convenience future to time out the resolution of `f` provided within the
/// duration provided.
///
/// If the `dur` is `None` then the returned future is equivalent to `f` (no
/// timeout) and otherwise the returned future will cancel `f` and resolve to an
/// error if the `dur` timeout elapses before `f` resolves.
pub fn timeout<F>(f: F, dur: Option<Duration>, handle: &Handle) -> MyFuture<F::Item>
where
    F: Future + 'static,
    F::Error: Into<Error>,
{
    let dur = match dur {
        Some(dur) => dur,
        None => return Box::new(f.map_err(|e| e.into())),
    };
    let timeout = Timeout::new(dur, handle).into_future().flatten();
    Box::new(f.select2(timeout).then(|res| match res {
        Ok(Either::A((item, _timeout))) => Ok(item),
        Err(Either::A((e, _timeout))) => Err(e.into()),
        Ok(Either::B(((), _item))) => Err("timed out".into()),
        Err(Either::B((e, _item))) => Err(e.into()),
    }))
}

pub fn init_logging(json: bool) {
    let instance_id_or_hostname = if json {
        get_ec2_instance_id().unwrap_or_else(|_| get_hostname().expect("Couldn't get_hostname"))
    } else {
        get_hostname().expect("Couldn't get_hostname")
    };
    let logger = if json {
        let drain = autojson::AutoJson::new(io::stdout())
            .add_default_keys()
            .add_key_value(o!(
                "Hostname" => instance_id_or_hostname,
                "Type" => "autopush_rs:log",
                "EnvVersion" => "2.0",
                "Logger" => format!("AutopushRust-{}", env!("CARGO_PKG_VERSION")),
            ))
            .build()
            .fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, o!())
    } else {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(
            drain,
            slog_o!(
                "Hostname" => instance_id_or_hostname,
                "Type" => "autopush_rs:log",
                "EnvVersion" => "2.0",
                "Logger" => format!("AutopushRust-{}", env!("CARGO_PKG_VERSION"))
            ),
        )
    };
    // XXX: cancel slog_scope's NoGlobalLoggerSet for now, it's difficult to
    // prevent it from potentially panicing during tests. reset_logging resets
    // the global logger during shutdown anyway
    slog_scope::set_global_logger(logger).cancel_reset();
    slog_stdlog::init().ok();
}

pub fn reset_logging() {
    let logger = slog::Logger::root(slog::Discard, o!());
    slog_scope::set_global_logger(logger).cancel_reset();
}
