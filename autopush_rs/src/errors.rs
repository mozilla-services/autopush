use std::any::Any;
use std::error;
use std::io;

use tungstenite;
use serde_json;
use futures::Future;

error_chain! {
    foreign_links {
        Ws(tungstenite::Error);
        Io(io::Error);
        Json(serde_json::Error);
    }

    errors {
        Thread(payload: Box<Any + Send>) {
            description("thread panicked")
        }
    }
}

pub type MyFuture<T> = Box<Future<Item = T, Error = Error>>;

pub trait FutureChainErr<T> {
    fn chain_err<F, E>(self, callback: F) -> MyFuture<T>
        where F: FnOnce() -> E + 'static,
              E: Into<ErrorKind>;
}

impl<F> FutureChainErr<F::Item> for F
    where F: Future + 'static,
          F::Error: error::Error + Send + 'static,
{
    fn chain_err<C, E>(self, callback: C) -> MyFuture<F::Item>
        where C: FnOnce() -> E + 'static,
              E: Into<ErrorKind>,
    {
        Box::new(self.then(|r| r.chain_err(callback)))
    }
}
