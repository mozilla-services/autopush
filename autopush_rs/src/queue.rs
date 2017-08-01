//! Thread-safe MPMC queue for working with Python and Rust
//!
//! This is created in Python and shared amongst a number of worker threads for
//! the receiving side, and then the sending side is done by the Rust thread
//! pushing requests over to Python. A `Sender` here is saved off in the
//! `Server` for sending messages.

use std::sync::mpsc;
use std::sync::Mutex;

use call::{AutopushPythonCall, PythonCall};
use rt::{self, AutopushError};

#[repr(C)]
pub struct AutopushQueue {
    tx: Mutex<Sender>,
    rx: Mutex<Option<mpsc::Receiver<Option<PythonCall>>>>,
}

pub type Sender = mpsc::Sender<Option<PythonCall>>;

fn _assert_kinds() {
    fn _assert<T: Send + Sync>() {}
    _assert::<AutopushQueue>();
}

#[no_mangle]
pub extern "C" fn autopush_queue_new(err: &mut AutopushError)
    -> *mut AutopushQueue
{
    rt::catch(err, || {
        let (tx, rx) = mpsc::channel();

        Box::new(AutopushQueue {
            tx: Mutex::new(tx),
            rx: Mutex::new(Some(rx)),
        })
    })
}

#[no_mangle]
pub extern "C" fn autopush_queue_recv(queue: *mut AutopushQueue,
                                      err: &mut AutopushError)
    -> *mut AutopushPythonCall
{
    rt::catch(err, || unsafe {
        let mut rx = (*queue).rx.lock().unwrap();
        let msg = match *rx {
            // this can't panic because we hold a reference to at least one
            // sender, so it'll always block waiting for the next message
            Some(ref rx) => rx.recv().unwrap(),

            // the "done" message was received by someone else, so we just keep
            // propagating that
            None => return None,
        };
        match msg {
            Some(msg) => Some(Box::new(AutopushPythonCall::new(msg))),

            // the senders are done, so all future calls shoudl bail out
            None => {
                *rx = None;
                None
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn autopush_queue_free(queue: *mut AutopushQueue) {
    rt::abort_on_panic(|| unsafe {
        Box::from_raw(queue);
    })
}

impl AutopushQueue {
    pub fn tx(&self) -> Sender {
        self.tx.lock().unwrap().clone()
    }
}
