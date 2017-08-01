from autopush_rs._native import ffi, lib
from twisted.application import service
from twisted.internet import reactor
import json

# TODO: can this global state be avoided? Need to figure out how to have some
#       contextual data referenced on a foreign thread and passed to
#       `_dispatch_server_ready_to_reactor` above. Unsure if this is actually
#       safe to do at all.
global_queue = None

# TODO: should use the new `ffi.def_extern` style callbacks, requires changes to
#       snaek.
@ffi.callback("AutopushPythonCall*(AutopushPythonCall*)")
def _dispatch_to_global_queue(ptr):
    global global_queue
    if global_queue is None:
        return ptr
    global_queue.put(AutopushCall(ptr))
    return ffi.NULL

def ffi_from_buffer(s):
    if s is None:
        return ffi.NULL
    else:
        return ffi.from_buffer(s)

def free(obj, free_fn):
    if obj.ffi is None:
        return
    ffi.gc(obj.ffi, None)
    free_fn(obj.ffi)
    obj.ffi = None

class AutopushServer(service.Service):
    def __init__(self, settings, queue):
        # type: (AutopushSettings, Queue) -> AutopushServer
        cfg = ffi.new('AutopushServerOptions*')
        cfg.auto_ping_interval = settings.auto_ping_interval
        cfg.auto_ping_timeout = settings.auto_ping_timeout
        cfg.close_handshake_timeout = settings.close_handshake_timeout
        cfg.max_connections = settings.max_connections
        cfg.open_handshake_timeout = 5
        cfg.port = settings.port
        cfg.ssl_cert = ffi_from_buffer(settings.ssl.cert)
        cfg.ssl_dh_param = ffi_from_buffer(settings.ssl.dh_param)
        cfg.ssl_key = ffi_from_buffer(settings.ssl.key)
        cfg.url = ffi_from_buffer(settings.ws_url)

        ptr = _call(lib.autopush_server_new, cfg)
        self.ffi = ffi.gc(ptr, lib.autopush_server_free)
        self.queue = queue

    def startService(self):
        global global_queue
        assert(global_queue is None)
        global_queue = self.queue
        _call(lib.autopush_server_start,
              self.ffi,
              _dispatch_to_global_queue)

    def stopService(self):
        global global_queue
        assert(global_queue is not None)
        _call(lib.autopush_server_stop, self.ffi)
        self._free_ffi()
        global_queue = None

    def _free_ffi(self):
        free(self, lib.autopush_server_free)

class AutopushCall:
    def __init__(self, ptr):
        self.ffi = ffi.gc(ptr, lib.autopush_python_call_free)

    def json(self):
        msg_ptr = _call(lib.autopush_python_call_input_ptr, self.ffi)
        msg_len = _call(lib.autopush_python_call_input_len, self.ffi) - 1
        buf = ffi.buffer(msg_ptr, msg_len)
        return json.loads(str(buf[:]))

    def complete(self, ret):
        s = json.dumps(ret)
        _call(lib.autopush_python_call_complete, self.ffi, s)
        self._free_ffi()

    def cancel(self):
        self._free_ffi()

    def _free_ffi(self):
        free(self, lib.autopush_python_call_free)

last_err = None

def _call(f, *args):
    # We cache errors across invocations of `_call` to avoid allocating a new
    # error each time we call an FFI function. Each function call, however,
    # needs a unique error, so take the global `last_err`, lazily initializing
    # it if necessary.
    global last_err
    my_err = last_err
    last_err = None
    if my_err is None:
        my_err = ffi.new('AutopushError*')

    # The error pointer is always the last argument, so pass that in and call
    # the actual FFI function. If the return value is nonzero then it was a
    # successful call and we can put our error back into the global slot
    # and return.
    args = args + (my_err,)
    ret = f(*args)
    if ffi.cast('size_t', ret) != 0:
        last_err = my_err
        return ret

    # If an error happened then it means that the Rust side of things panicked
    # which we need to handle here. Acquire the string from the error, if
    # available, and re-raise as a python `RuntimeError`.
    #
    # Note that we're also careful here to clean up the error's internals to
    # avoid memory leaks and then once we're completely done we can restore our
    # local error to its global position.
    errln = lib.autopush_error_msg_len(my_err);
    if errln > 0:
        ptr = lib.autopush_error_msg_ptr(my_err)
        msg = 'rust panic: ' + ffi.buffer(ptr, errln)[:]
        exn = RuntimeError(msg)
    else:
        exn = RuntimeError('unknown error in rust')
    lib.autopush_error_cleanup(my_err)
    last_err = my_err
    raise exn

