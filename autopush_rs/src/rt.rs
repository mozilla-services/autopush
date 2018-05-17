//! Runtime support for calling in and out of Python
//!
//! This module provides a number of utilities for interfacing with Python in a
//! safe fashion. It's primarily used to handle *panics* in Rust which otherwise
//! could cause segfaults or strange crashes if otherwise unhandled.
//!
//! The current protocol for Python calling into Rust looks like so:
//!
//! * Primarily, all panics are caught in Rust. Panics are intended to be
//!   translated to exceptions in Python to indicate a fatal error happened in
//!   Rust.
//!
//! * Almost all FFI functions take a `&mut AutopushError` as their last
//!   argument. This argument is used to capture the reason of a panic so it can
//!   later be introspected in Python to generate a runtime assertion. The
//!   handling of `AutopushError` is intended to be relatively transparent by
//!   just needing to pass it to some functions in this module.
//!
//! * A `UnwindGuard` is provided for stateful objects persisted across FFI
//!   function calls. If a Rust function panics it's typically not intended to
//!   be rerun at a later date with the same arguments, so what `UnwindGuard`
//!   will do is only provide access to the internals *until* a panic happens.
//!   After a panic then access to the internals will be gated and forbidden
//!   until destruction. This should help prevent bugs from becoming worse bugs
//!   quickly (in theory).
//!
//!   All Rust objects shared with Python have an `UnwindGuard` internally which
//!   protects all of the state that Rust is fiddling with.
//!
//! Typically you can just look at some other examples of `#[no_mangle]`
//! functions throughout this crate and copy those idioms, otherwise there's
//! documentation on each specific function here.

use std::any::Any;
use std::cell::Cell;
use std::mem;
use std::panic;
use std::ptr;

/// Generic error which is used on all function calls from Python into Rust.
///
/// This is allocated in Python and reused across function calls when possible.
/// It effectively stores a `Box<Any>` which is what's created whenever a Rust
/// thread panics. This `Box<Any>` may store an object, a string, etc.
#[repr(C)]
pub struct AutopushError {
    p1: usize,
    p2: usize,
}

impl AutopushError {
    /// Attempts to extract the error message out of this inernal `Box<Any>`.
    /// This may fail if the `Any` doesn't look like it can be stringified
    /// though.
    fn string(&self) -> Option<&str> {
        assert!(self.p1 != 0);
        assert!(self.p2 != 0);
        let any: &Any = unsafe { mem::transmute((self.p1, self.p2)) };
        // Similar to what libstd does, only check for `&'static str` and
        // `String`.
        any.downcast_ref::<&'static str>()
            .map(|s| &s[..])
            .or_else(|| any.downcast_ref::<String>().map(|s| &s[..]))
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

    /// Deallocates the internal `Box<Any>`, freeing the resources behind it.
    unsafe fn cleanup(&mut self) {
        mem::transmute::<_, Box<Any + Send>>((self.p1, self.p2));
        self.p1 = 0;
        self.p2 = 0;
    }
}

/// Acquires the length of the error message in this error, or returns 0 if
/// there is no error message.
#[no_mangle]
pub extern "C" fn autopush_error_msg_len(err: *const AutopushError) -> usize {
    abort_on_panic(|| unsafe { (*err).string().map_or(0, |s| s.len()) })
}

/// Returns the data pointer of the error message, if any. If not present
/// returns null.
#[no_mangle]
pub extern "C" fn autopush_error_msg_ptr(err: *const AutopushError) -> *const u8 {
    abort_on_panic(|| unsafe { (*err).string().map_or(ptr::null(), |s| s.as_ptr()) })
}

/// Deallocates the internal `Box<Any>`, freeing any resources it contains.
///
/// The error itself can continue to be reused for future function calls.
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
        Self {
            poisoned: Cell::new(false),
            inner: t,
        }
    }

    /// This function is intended to be immediately called in an FFI callback,
    /// and will execute the closure `f` catching panics.
    ///
    /// The `err` provided will be filled in if the function panics.
    ///
    /// The closure `f` will execute with the state this `UnwindGuard` is
    /// internally protecting, allowing it shared access to the various pieces.
    /// The closure's return value is then also automatically converted to an
    /// FFI-safe value through the `AbiInto` trait. Various impls for this trait
    /// can be found below (possible types to return).
    ///
    /// Note that if this `UnwindGuard` previously caught a panic then the
    /// closure `f` will not be executed. This function will immediately return
    /// with the "null" return value to propagate the panic again.
    pub fn catch<F, R>(&self, err: &mut AutopushError, f: F) -> R::AbiRet
    where
        F: FnOnce(&T) -> R,
        R: AbiInto,
    {
        err.assert_empty();
        if self.poisoned.get() {
            err.fill(Box::new(String::from("accessing poisoned object")));
            return R::null();
        }

        // The usage of `AssertUnwindSafe` should be ok here because as
        // soon as we see this closure panic we'll disallow all further
        // access to the internals of `self`.
        let mut panicked = true;
        let ret = catch(
            err,
            panic::AssertUnwindSafe(|| {
                let ret = f(&self.inner);
                panicked = false;
                ret
            }),
        );
        if panicked {
            self.poisoned.set(true);
        }
        ret
    }
}

/// Catches a panic within the closure `f`, filling in `err` if a panic happens.
///
/// This is typically only used for constructors where there's no state
/// persisted across calls.
pub fn catch<T, F>(err: &mut AutopushError, f: F) -> T::AbiRet
where
    F: panic::UnwindSafe + FnOnce() -> T,
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
        },
    }
}

/// Helper to *abort* on panics rather than catch them and communicate to
/// python.
///
/// This should be rarely used but is used when executing destructors in Rust,
/// which should be infallible (and this is just a double-check that they are).
pub fn abort_on_panic<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
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
    r
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
        Self::into_raw(self)
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
