import json

from autopush_rs._native import ffi, lib


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


class AutopushServer(object):
    def __init__(self, conf, message_tables, queue):
        # type: (AutopushConfig, List[str], AutopushQueue) -> AutopushServer
        cfg = ffi.new('AutopushServerOptions*')
        cfg.auto_ping_interval = conf.auto_ping_interval
        cfg.auto_ping_timeout = conf.auto_ping_timeout
        cfg.close_handshake_timeout = conf.close_handshake_timeout
        cfg.max_connections = conf.max_connections
        cfg.open_handshake_timeout = 5
        cfg.port = conf.port
        cfg.router_port = conf.router_port
        cfg.router_url = ffi_from_buffer(conf.router_url)
        cfg.ssl_cert = ffi_from_buffer(conf.ssl.cert)
        cfg.ssl_dh_param = ffi_from_buffer(conf.ssl.dh_param)
        cfg.ssl_key = ffi_from_buffer(conf.ssl.key)
        cfg.json_logging = not conf.human_logs
        cfg.statsd_host = ffi_from_buffer(conf.statsd_host)
        cfg.statsd_port = conf.statsd_port
        cfg.router_table_name = ffi_from_buffer(conf.router_table.tablename)
        # XXX: keepalive
        self.message_table_names = ','.join(name.encode('utf-8') for name in message_tables)
        cfg.message_table_names = ffi_from_buffer(self.message_table_names)
        cfg.megaphone_api_url = ffi_from_buffer(conf.megaphone_api_url)
        cfg.megaphone_api_token = ffi_from_buffer(conf.megaphone_api_token)
        cfg.megaphone_poll_interval = conf.megaphone_poll_interval

        ptr = _call(lib.autopush_server_new, cfg)
        self.ffi = ffi.gc(ptr, lib.autopush_server_free)
        self.queue = queue

    def startService(self):
        _call(lib.autopush_server_start,
              self.ffi,
              self.queue.ffi)

    def stopService(self):
        if self.ffi is None:
            return
        _call(lib.autopush_server_stop, self.ffi)
        self._free_ffi()

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


class AutopushQueue:
    def __init__(self):
        ptr = _call(lib.autopush_queue_new)
        self.ffi = ffi.gc(ptr, lib.autopush_queue_free)

    def recv(self):
        if self.ffi is None:
            return None
        ret = _call(lib.autopush_queue_recv, self.ffi)
        if ffi.cast('size_t', ret) == 1:
            return None
        else:
            return AutopushCall(ret)


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
