extern crate futures;
extern crate libc;
extern crate tokio_core;
extern crate tokio_tungstenite;

use std::panic;
use std::ptr;
use std::mem;
use std::any::Any;
use std::cell::Cell;

#[repr(C)]
pub struct AutopushError {
    p1: usize,
    p2: usize,
}

impl AutopushError {
    fn string(&self) -> Option<&str> {
        assert!(self.p1 != 0);
        assert!(self.p2 != 0);
        let any: &Any = unsafe {
            mem::transmute((self.p1, self.p2))
        };
        any.downcast_ref::<&'static str>()
            .map(|s| &s[..])
            .or_else(|| {
                any.downcast_ref::<String>().map(|s| &s[..])
            })
    }

    fn assert_empty(&self) {
        assert_eq!(self.p1, 0);
        assert_eq!(self.p2, 0);
    }

    fn fill(&mut self, any: Box<Any>) {
        self.assert_empty();
        unsafe {
            let ptrs: (usize, usize) = mem::transmute(any);
            self.p1 = ptrs.0;
            self.p2 = ptrs.1;
        }
    }

    unsafe fn cleanup(&mut self) {
        mem::transmute::<_, Box<Any+Send>>((self.p1, self.p2));
        self.p1 = 0;
        self.p2 = 0;
    }
}

#[no_mangle]
pub extern "C" fn autopush_error_msg_len(err: *const AutopushError) -> usize {
    abort_on_panic(|| unsafe {
        (*err).string().map(|s| s.len()).unwrap_or(0)
    })
}

#[no_mangle]
pub extern "C" fn autopush_error_msg_ptr(err: *const AutopushError) -> *const u8 {
    abort_on_panic(|| unsafe {
        (*err).string().map(|s| s.as_ptr()).unwrap_or(ptr::null())
    })
}

#[no_mangle]
pub unsafe extern "C" fn autopush_error_cleanup(err: *mut AutopushError) {
    abort_on_panic(|| {
        (&mut *err).cleanup();
    });
}

/// Helper structure to provide "unwind safety" to ensure we don't reuse values
/// accidentally after a panic.
pub struct UnwindGuard<T> {
    poisoned: Cell<bool>,
    inner: T,
}

impl<T> UnwindGuard<T> {
    pub fn new(t: T) -> UnwindGuard<T> {
        UnwindGuard {
            poisoned: Cell::new(false),
            inner: t,
        }
    }

    pub fn catch<F, R>(&self, err: &mut AutopushError, f: F) -> R::AbiRet
        where F: FnOnce(&T) -> R,
              R: AbiInto,
    {
        err.assert_empty();
        if self.poisoned.get() {
            err.fill(Box::new(String::from("accessing poisoned object")));
            return R::null()
        }

        // The usage of `AssertUnwindSafe` should be ok here because as
        // soon as we see this closure panic we'll disallow all further
        // access to the internals of `self`.
        let mut panicked = true;
        let ret = catch(err, panic::AssertUnwindSafe(|| {
            let ret = f(&self.inner);
            panicked = false;
            return ret
        }));
        if panicked {
            self.poisoned.set(true);
        }
        return ret
    }
}

pub fn catch<T, F>(err: &mut AutopushError, f: F) -> T::AbiRet
    where F: panic::UnwindSafe + FnOnce() -> T,
          T: AbiInto,
{
    err.assert_empty();

    match panic::catch_unwind(f) {
        Ok(t) => t.abi_into(),
        Err(e) => unsafe {
            let ptrs: (usize, usize) = mem::transmute(e);
            err.p1 = ptrs.0;
            err.p2 = ptrs.1;
            T::null()
        }
    }
}

pub fn abort_on_panic<F, R>(f: F) -> R
    where F: FnOnce() -> R,
{
    struct Bomb {
        active: bool,
    }

    impl Drop for Bomb {
        fn drop(&mut self) {
            if self.active {
                panic!("unexpected panic, aborting process");
            }
        }
    }

    let mut bomb = Bomb { active: true };
    let r = f();
    bomb.active = false;
    return r
}

pub trait AbiInto {
    type AbiRet;

    fn abi_into(self) -> Self::AbiRet;
    fn null() -> Self::AbiRet;
}

impl AbiInto for () {
    type AbiRet = i32;

    fn abi_into(self) -> i32 {
        1
    }

    fn null() -> i32 {
        0
    }
}

impl<T> AbiInto for Box<T> {
    type AbiRet = *mut T;

    fn abi_into(self) -> *mut T {
        Box::into_raw(self)
    }

    fn null() -> *mut T {
        ptr::null_mut()
    }
}

impl<T> AbiInto for Option<Box<T>> {
    type AbiRet = *mut T;

    fn abi_into(self) -> *mut T {
        match self {
            Some(b) => Box::into_raw(b),
            None => 1 as *mut T,
        }
    }

    fn null() -> *mut T {
        ptr::null_mut()
    }
}

impl<T> AbiInto for *const T {
    type AbiRet = *const T;

    fn abi_into(self) -> *const T {
        self
    }

    fn null() -> *const T {
        ptr::null()
    }
}

impl<T> AbiInto for *mut T {
    type AbiRet = *mut T;

    fn abi_into(self) -> *mut T {
        self
    }

    fn null() -> *mut T {
        ptr::null_mut()
    }
}

impl AbiInto for usize {
    type AbiRet = usize;

    fn abi_into(self) -> usize {
        self + 1
    }

    fn null() -> usize {
        0
    }
}
