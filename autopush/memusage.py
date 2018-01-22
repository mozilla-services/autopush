"""Produces memory usage information"""
import gc
import objgraph
import os
import resource
import subprocess
import tempfile
import zlib
from StringIO import StringIO
from typing import Optional  # noqa

from autopush.gcdump import Stat

from cffi import FFI


# cffi's API mode is preferable but it would assume jemalloc is always
# available (and we LD_PRELOAD it)
ffi = FFI()
ffi.cdef("""
int malloc_info(int options, FILE *stream);
void malloc_stats_print(void (*write_cb) (void *, const char *),
                        void *cbopaque, const char *opts);
""")
lib = ffi.dlopen(None)


def memusage(do_dump_rpy_heap=True, do_objgraph=True):
    """Returning a str of memory usage stats"""
    # type: (Optional[bool], Optional[bool]) -> str
    def trap_err(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:  # pragma: nocover
            # include both __str/repr__, sometimes one's useless
            buf.writelines([func.__name__, ': ', repr(e), ': ', str(e)])

    buf = StringIO()
    rusage = trap_err(resource.getrusage, resource.RUSAGE_SELF)
    buf.writelines([repr(rusage), '\n\n'])
    trap_err(pmap_extended, buf)
    trap_err(jemalloc_stats, buf)
    trap_err(glibc_malloc_info, buf)
    if do_dump_rpy_heap:
        # dump rpython's heap before objgraph potentially pollutes the
        # heap with its heavy workload
        trap_err(dump_rpy_heap, buf)
    trap_err(get_stats_asmmemmgr, buf)
    buf.write('\n\n')
    if do_objgraph:
        trap_err(objgraph.show_most_common_types, limit=0, file=buf)
    return buf.getvalue()


def pmap_extended(stream):
    """Write pmap (w/ the most extended stats supported) to stream"""
    pid = str(os.getpid())
    # -XX/-X are recent linux only
    ex_args = ['XX', 'X', 'x']
    while True:
        cmd = ['pmap', '-' + ex_args.pop(0), pid]
        try:
            pmap = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:  # pragma: nocover
            if not ex_args:
                raise
        else:
            stream.writelines([' '.join(cmd[:2]), '\n', pmap, '\n\n'])
            break


def dump_rpy_heap(stream):  # pragma: nocover
    """Write PyPy's gcdump to the specified stream"""
    if not hasattr(gc, '_dump_rpy_heap'):
        # not PyPy
        return

    with tempfile.NamedTemporaryFile('wb') as fp:
        gc._dump_rpy_heap(fp.fileno())
        try:
            fpsize = os.stat(fp.name).st_size
        except OSError:
            pass
        else:
            stream.write("{} size: {}\n".format(fp.name, fpsize))
        stat = Stat()
        stat.summarize(fp.name, stream=None)
    stat.load_typeids(zlib.decompress(gc.get_typeids_z()).split("\n"))
    stream.write('\n\n')
    stat.print_summary(stream)


def get_stats_asmmemmgr(stream):  # pragma: nocover
    """Write PyPy's get_stats_asmmemmgr to the specified stream

    (The raw memory currently used by the JIT backend)

    """
    try:
        import pypyjit
    except ImportError:
        # not PyPy or no jit?
        return

    stream.write('\n\nget_stats_asmmemmgr: ')
    stream.write(repr(pypyjit.get_stats_asmmemmgr()))
    stream.write('\n')


def glibc_malloc_info(stream):
    """Write glib malloc's malloc_info(3)"""
    with tempfile.NamedTemporaryFile('wb+') as fp:
        if not lib.malloc_info(0, fp.file):
            fp.seek(0)
            stream.writelines(fp.readlines())


def jemalloc_stats(stream):
    """Write jemalloc's malloc_stats_print()"""
    try:
        malloc_stats_print = lib.malloc_stats_print
    except AttributeError:
        # not using jemalloc
        return
    malloc_stats_print(_jemalloc_write_cb, ffi.new_handle(stream), ffi.NULL)
    stream.write('\n')


@ffi.callback("void (*write_cb) (void *, const char *)")
def _jemalloc_write_cb(handle, msg):
    """Callback for jemalloc's malloc_stats_print

    Writes to a Python stream passed via the cbopaque pointer

    """
    stream = ffi.from_handle(handle)
    stream.write(ffi.string(msg))
