//! Various small utilities accumulated over time for the WebPush server
use std::env;
use std::time::Duration;
use std::sync::atomic::{ATOMIC_BOOL_INIT, AtomicBool, Ordering};

use env_logger;
use futures::future::{Either, Future, IntoFuture};
use log::LogRecord;
use serde_json;
use tokio_core::reactor::{Handle, Timeout};

use errors::*;

mod send_all;
mod rc;

pub use self::send_all::MySendAll;
pub use self::rc::RcObject;

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

static LOG_JSON: AtomicBool = ATOMIC_BOOL_INIT;

pub fn init_logging(json: bool) {
    // We only initialize once, so ignore initialization errors related to
    // calling this function twice.
    let mut builder = env_logger::LogBuilder::new();

    if env::var("RUST_LOG").is_ok() {
        builder.parse(&env::var("RUST_LOG").unwrap());
    }

    builder.target(env_logger::LogTarget::Stdout).format(
        maybe_json_record,
    );

    if builder.init().is_ok() {
        LOG_JSON.store(json, Ordering::SeqCst);
    }
}

fn maybe_json_record(record: &LogRecord) -> String {
    #[derive(Serialize)]
    struct Message<'a> {
        msg: String,
        level: String,
        target: &'a str,
        module: &'a str,
        file: &'a str,
        line: u32,
    }

    if LOG_JSON.load(Ordering::SeqCst) {
        serde_json::to_string(&Message {
            msg: record.args().to_string(),
            level: record.level().to_string(),
            target: record.target(),
            module: record.location().module_path(),
            file: record.location().file(),
            line: record.location().line(),
        }).unwrap()
    } else {
        format!(
            "{}:{}: {}",
            record.level(),
            record.location().module_path(),
            record.args()
        )
    }
}
