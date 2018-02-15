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

// Hold a reference to the log guards for scoped logging which requires these to stay alive
// for the implicit logger to be passed into logging calls
pub struct LogGuards {
    _scope_guard: slog_scope::GlobalLoggerGuard,
}

pub fn init_logging(json: bool) -> LogGuards {
    let instance_id_or_hostname =
        get_ec2_instance_id().unwrap_or_else(|_| get_hostname().expect("Couldn't get_hostname"));
    if json {
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
        let logger = slog::Logger::root(drain, o!());
        let _scope_guard = slog_scope::set_global_logger(logger);
        slog_stdlog::init().ok();
        LogGuards {
            _scope_guard: _scope_guard,
        }
    } else {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let logger = slog::Logger::root(
            drain,
            slog_o!(
                "Hostname" => instance_id_or_hostname,
                "Type" => "autopush_rs:log",
                "EnvVersion" => "2.0",
                "Logger" => format!("AutopushRust-{}", env!("CARGO_PKG_VERSION"))
            ),
        );
        let _scope_guard = slog_scope::set_global_logger(logger);
        slog_stdlog::init().ok();
        LogGuards {
            _scope_guard: _scope_guard,
        }
    }
}
