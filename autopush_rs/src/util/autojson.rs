// {{{ Crate docs
//! JSON `Drain` for `slog-rs`
//!
//! ```
//! #[macro_use]
//! extern crate slog;
//! extern crate slog_json;
//!
//! use slog::Drain;
//! use std::sync::Mutex;
//!
//! fn main() {
//!     let root = slog::Logger::root(
//!         Mutex::new(slog_json::Json::default(std::io::stderr())).map(slog::Fuse),
//!         o!("version" => env!("CARGO_PKG_VERSION"))
//!     );
//! }
//! ```
// }}}
use chrono;
use serde;
use serde::ser::SerializeMap;
use serde_json;
use slog;
use slog::Record;
use slog::{FnValue, PushFnValue};
use slog::{OwnedKVList, SendSyncRefUnwindSafeKV, KV};
use std;
use std::io::Cursor;
use std::{fmt, io, result};

use std::cell::RefCell;
use std::fmt::Write;

// }}}

// {{{ Serialize
thread_local! {
    static TL_BUF: RefCell<String> = RefCell::new(String::with_capacity(128))
}

/// `slog::Serializer` adapter for `serde::Serializer`
///
/// Newtype to wrap serde Serializer, so that `Serialize` can be implemented
/// for it
struct SerdeSerializer<S: serde::Serializer> {
    /// Current state of map serializing: `serde::Seriaizer::MapState`
    ser_map: S::SerializeMap,
}

impl<S: serde::Serializer> SerdeSerializer<S> {
    /// Start serializing map of values
    fn start(ser: S, len: Option<usize>) -> result::Result<Self, slog::Error> {
        let ser_map = ser.serialize_map(len)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "serde serialization error"))?;
        Ok(SerdeSerializer { ser_map: ser_map })
    }

    /// Finish serialization, and return the serializer
    fn end(self) -> std::result::Result<S::Ok, S::Error> {
        self.ser_map.end()
    }
}

macro_rules! impl_m(
    ($s:expr, $key:expr, $val:expr) => ({
        try!($s.ser_map.serialize_entry($key, $val)
             .map_err(|_| io::Error::new(io::ErrorKind::Other, "serde serialization error")));
        Ok(())
    });
);

impl<S> slog::Serializer for SerdeSerializer<S>
where
    S: serde::Serializer,
{
    fn emit_bool(&mut self, key: &str, val: bool) -> slog::Result {
        impl_m!(self, key, &val)
    }

    fn emit_unit(&mut self, key: &str) -> slog::Result {
        impl_m!(self, key, &())
    }

    fn emit_char(&mut self, key: &str, val: char) -> slog::Result {
        impl_m!(self, key, &val)
    }

    fn emit_none(&mut self, key: &str) -> slog::Result {
        let val: Option<()> = None;
        impl_m!(self, key, &val)
    }
    fn emit_u8(&mut self, key: &str, val: u8) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_i8(&mut self, key: &str, val: i8) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_u16(&mut self, key: &str, val: u16) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_i16(&mut self, key: &str, val: i16) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_usize(&mut self, key: &str, val: usize) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_isize(&mut self, key: &str, val: isize) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_u32(&mut self, key: &str, val: u32) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_i32(&mut self, key: &str, val: i32) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_f32(&mut self, key: &str, val: f32) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_u64(&mut self, key: &str, val: u64) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_i64(&mut self, key: &str, val: i64) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_f64(&mut self, key: &str, val: f64) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_str(&mut self, key: &str, val: &str) -> slog::Result {
        impl_m!(self, key, &val)
    }
    fn emit_arguments(&mut self, key: &str, val: &fmt::Arguments) -> slog::Result {
        TL_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();

            buf.write_fmt(*val).unwrap();

            let res = { || impl_m!(self, key, &*buf) }();
            buf.clear();
            res
        })
    }
}
// }}}

// {{{ Json
/// Json `Drain`
///
/// Each record will be printed as a Json map
/// to a given `io`
pub struct AutoJson<W: io::Write> {
    values: Vec<OwnedKVList>,
    io: RefCell<W>,
}

impl<W> AutoJson<W>
where
    W: io::Write,
{
    /// Build custom `Json` `Drain`
    #[cfg_attr(feature = "cargo-clippy", allow(new_ret_no_self))]
    pub fn new(io: W) -> AutoJsonBuilder<W> {
        AutoJsonBuilder::new(io)
    }
}

// }}}

// {{{ JsonBuilder
/// Json `Drain` builder
///
/// Create with `Json::new`.
pub struct AutoJsonBuilder<W: io::Write> {
    values: Vec<OwnedKVList>,
    io: W,
}

impl<W> AutoJsonBuilder<W>
where
    W: io::Write,
{
    fn new(io: W) -> Self {
        AutoJsonBuilder { values: vec![], io }
    }

    /// Build `Json` `Drain`
    ///
    /// This consumes the builder.
    pub fn build(self) -> AutoJson<W> {
        AutoJson {
            values: self.values,
            io: RefCell::new(self.io),
        }
    }

    /// Add custom values to be printed with this formatter
    pub fn add_key_value<T>(mut self, value: slog::OwnedKV<T>) -> Self
    where
        T: SendSyncRefUnwindSafeKV + 'static,
    {
        self.values.push(value.into());
        self
    }

    /// Add default key-values:
    ///
    /// * `ts` - timestamp
    /// * `level` - record logging level name
    /// * `msg` - msg - formatted logging message
    pub fn add_default_keys(self) -> Self {
        self.add_key_value(o!(
                "Timestamp" => PushFnValue(move |_ : &Record, ser| {
                    let now = chrono::Utc::now();
                    let nsec: i64 = (now.timestamp() as i64) * 1_000_000_000;
                    let nsec: i64 = nsec + (now.timestamp_subsec_nanos() as i64);
                    ser.emit(nsec)
                }),
                "Severity" => FnValue(move |rinfo : &Record| {
                    if rinfo.level() == slog::Level::Error {
                        3
                    } else {
                        5
                    }
                })
            ))
    }
}

impl<W> slog::Drain for AutoJson<W>
where
    W: io::Write,
{
    type Ok = ();
    type Err = io::Error;
    fn log(&self, rinfo: &Record, logger_values: &OwnedKVList) -> io::Result<()> {
        // XXX: UGLY HACK HERE
        // First write out the structure without the Fields nested
        let mut buff = Cursor::new(Vec::new());
        {
            let mut serializer = serde_json::Serializer::new(&mut buff);
            let mut serializer = SerdeSerializer::start(&mut serializer, None)?;
            for kv in &self.values {
                kv.serialize(rinfo, &mut serializer)?;
            }
            logger_values.serialize(rinfo, &mut serializer)?;
            let fields_placeholder = kv!("Fields" => "00PLACEHOLDER00");
            fields_placeholder.serialize(rinfo, &mut serializer)?;
            let res = serializer.end();
            res.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        };
        let payload = String::from_utf8(buff.into_inner()).unwrap();

        // Now write out just the Fields entry we replace with
        let mut buff = Cursor::new(Vec::new());
        {
            let mut serializer = serde_json::Serializer::new(&mut buff);
            let mut serializer = SerdeSerializer::start(&mut serializer, None)?;
            let msg = kv!("message" => format!("{}", rinfo.msg()));
            msg.serialize(rinfo, &mut serializer)?;
            rinfo.kv().serialize(rinfo, &mut serializer)?;
        };
        let message = String::from_utf8(buff.into_inner()).unwrap();

        // And now we replace the placeholder with the contents
        let mut payload = payload.replace("\"00PLACEHOLDER00\"", message.as_str());
        // For some reason the replace loses an end }
        payload.push_str("}");

        let mut io = self.io.borrow_mut();
        io.write_all(payload.as_bytes())?;
        io.write_all(b"\n")?;
        Ok(())
    }
}
// }}}
