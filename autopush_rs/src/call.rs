//! Implementation of calling methods/objects in python
//!
//! The main `AutopushServer` has a channel that goes back to the main python
//! thread, and that's used to send instances of `PythonCall` from the Tokio
//! thread to the Python thread. A `PythonCall` is constructed via the
//! `new` constructor and will sling a json-serialized form of the arguments
//! and output to/from Python.
//!
//! The main python thread will receive these messages and dispatch them
//! appropriately, completing the message when the value is ready.
//!
//! # Examples
//!
//! ```
//! use call::PythonCall;
//!
//! let (call, rx) = PythonCall::new("add", (1, 2));
//! send_to_python_thread(call);
//!
//! // rx is now a future of the `add` call with the arguments (1, 2),
//! // and it'll get completed from python.
//! ```

use std::cell::RefCell;
use std::ffi::CStr;

use errors::*;
use futures::Future;
use futures::sync::oneshot;
use libc::c_char;
use serde::de;
use serde::ser;
use serde_json;

use rt::{self, UnwindGuard, AutopushError};

#[repr(C)]
pub struct AutopushPythonCall {
    inner: UnwindGuard<Inner>,
}

struct Inner {
    input: String,
    done: RefCell<Option<Box<FnBox>>>,
}

pub struct PythonCall {
    input: String,
    output: Box<FnBox>,
}

#[no_mangle]
pub extern "C" fn autopush_python_call_input_ptr(call: *mut AutopushPythonCall,
                                                 err: &mut AutopushError)
    -> *const u8
{
    unsafe {
        (*call).inner.catch(err, |call| {
            call.input.as_ptr()
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_python_call_input_len(call: *mut AutopushPythonCall,
                                                 err: &mut AutopushError)
    -> usize
{
    unsafe {
        (*call).inner.catch(err, |call| {
            call.input.len()
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_python_call_complete(call: *mut AutopushPythonCall,
                                                input: *const c_char,
                                                err: &mut AutopushError)
    -> i32
{
    unsafe {
        (*call).inner.catch(err, |call| {
            let input = CStr::from_ptr(input).to_str().unwrap();
            call.done.borrow_mut().take().unwrap().call(input);
        })
    }
}

#[no_mangle]
pub extern "C" fn autopush_python_call_free(call: *mut AutopushPythonCall) {
    rt::abort_on_panic(|| unsafe {
        Box::from_raw(call);
    })
}

impl AutopushPythonCall {
    pub fn new(call: PythonCall) -> AutopushPythonCall {
        AutopushPythonCall {
            inner: UnwindGuard::new(Inner {
                input: call.input,
                done: RefCell::new(Some(call.output)),
            }),
        }
    }

    fn _new<F>(input: String, f: F) -> AutopushPythonCall
        where F: FnOnce(&str) + Send + 'static,
    {
        AutopushPythonCall {
            inner: UnwindGuard::new(Inner {
                input: input,
                done: RefCell::new(Some(Box::new(f))),
            }),
        }
    }
}

trait FnBox: Send {
    fn call(self: Box<Self>, input: &str);
}

impl<F: FnOnce(&str) + Send> FnBox for F {
    fn call(self: Box<Self>, input: &str) {
        (*self)(input)
    }
}

impl PythonCall {
    pub fn new<T, U>(name: &str, args: T) -> (PythonCall, MyFuture<U>)
        where T: ser::Serialize,
              U: for<'de> de::Deserialize<'de> + 'static,
    {
        #[derive(Serialize)]
        struct Input<'a, T> {
            name: &'a str,
            args: T,
        }

        let (tx, rx) = oneshot::channel();
        let call = PythonCall {
            input: serde_json::to_string(&Input {
                name: name,
                args: args,
            }).unwrap(),
            output: Box::new(|json: &str| {
                drop(tx.send(json.to_string()));
            }),
        };
        let rx = Box::new(rx.then(|res| {
            match res {
                Ok(s) => Ok(serde_json::from_str(&s)?),
                Err(_) => Err("call canceled from python".into()),
            }
        }));
        (call, rx)
    }
}
