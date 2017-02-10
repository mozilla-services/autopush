"""Produces memory usage information"""
import gc
import objgraph
import os
import resource
import subprocess
import tempfile
import zlib
from StringIO import StringIO

from autopush.gcdump import Stat


def memusage():
    """Returning a str of memory usage stats"""
    # type() -> str
    def trap_err(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:  # pragma: nocover
            # include both __str/repr__, sometimes one's useless
            buf.writelines([func.__name__, ': ', repr(e), ': ', str(e)])

    buf = StringIO()
    rusage = trap_err(resource.getrusage, resource.RUSAGE_SELF)
    buf.writelines([repr(rusage), '\n\n'])
    trap_err(objgraph.show_most_common_types, limit=0, file=buf)
    buf.write('\n\n')
    pmap = trap_err(subprocess.check_output, ['pmap', '-x', str(os.getpid())],
                    stderr=subprocess.STDOUT)
    buf.writelines([pmap, '\n\n'])
    trap_err(dump_rpy_heap, buf)
    return buf.getvalue()


def dump_rpy_heap(stream):
    """Write PyPy's gcdump to the specified stream"""
    if not hasattr(gc, '_dump_rpy_heap'):
        # not PyPy
        return

    with tempfile.NamedTemporaryFile('wb') as fp:
        gc._dump_rpy_heap(fp.fileno())
        stream.write("{} size: {}\n".format(fp.name, os.stat(fp.name).st_size))
        stat = Stat()
        stat.summarize(fp.name, stream=None)
    stat.load_typeids(zlib.decompress(gc.get_typeids_z()).split("\n"))
    stream.write('\n\n')
    stat.print_summary(stream)
