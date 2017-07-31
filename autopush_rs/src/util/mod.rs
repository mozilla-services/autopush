use std::time::Duration;

use futures::future::{Either, Future, IntoFuture};
use tokio_core::reactor::{Handle, Timeout};

use errors::*;

mod send_all;
mod rc;

pub use self::send_all::MySendAll;
pub use self::rc::RcObject;

pub fn timeout<F>(f: F, dur: Option<Duration>, handle: &Handle) -> MyFuture<F::Item>
    where F: Future + 'static,
          F::Error: Into<Error>,
{
    let dur = match dur {
        Some(dur) => dur,
        None => return Box::new(f.map_err(|e| e.into())),
    };
    let timeout = Timeout::new(dur, handle).into_future().flatten();
    Box::new(f.select2(timeout).then(|res| {
        match res {
            Ok(Either::A((item, _timeout))) => Ok(item),
            Err(Either::A((e, _timeout))) => Err(e.into()),
            Ok(Either::B(((), _item))) => Err("timed out".into()),
            Err(Either::B((e, _item))) => Err(e.into()),
        }
    }))
}
