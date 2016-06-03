from collections import defaultdict
import time

try:
    from nose.plugins import Plugin
except ImportError:
    class Plugin(object):
        pass


try:
    from pympler import asizeof
except:
    asizeof = None


_testing = False
_compact = True
_excludes = []
tracked_objects = defaultdict(lambda: [])
test_results = {}
open_objects = {}


def track_object(obj, msg=None):
    if not asizeof:
        return

    # Only track if testing
    sizer = asizeof.Asizer()
    sizer.exclude_types(_excludes)
    if not _testing:
        return

    tracked_objects[id(obj)].append(
        (time.time(), obj, sizer.asizeof(obj) / 1024.0, msg)
    )


class ObjectTracker(Plugin):  # pragma: nocover
    name = "object-tracker"

    def startTest(self, test):
        global _testing, _excludes
        _testing = getattr(test, "track_objects", False)
        if _testing:
            _excludes = getattr(test, "track_objects_excludes", [])

    def stopTest(self, test):
        global tracked_objects, open_objects
        if hasattr(test, "track_objects"):
            test_name = test.id()
            if tracked_objects:
                test_results[test_name] = tracked_objects.copy()

        tracked_objects = defaultdict(lambda: [])
        open_objects = {}

    def report(self, stream):
        stream.write("\n\nObject Tracking Results\n")
        for test in sorted(test_results.keys()):
            tracked = test_results[test]
            stream.write("\n%s\n" % test)

            for _, objects in tracked.items():
                stream.write("\t%s" % objects[0][1])
                if not _compact:
                    stream.write("\n")
                sorted_tracked = sorted(objects, key=lambda v: v[0])
                values = map(lambda v: v[2], objects)
                min_val = min(values)
                max_val = max(values)
                delta = max_val - min_val
                if _compact:
                    stream.write("  Delta: {:,.2f}\n".format(delta))
                    continue

                for t, _, size, msg in sorted_tracked:
                    ft = "%.2f" % t
                    stream.write("\t\t%20s" % ft)
                    stream.write("  {:<25}".format(msg))
                    stream.write("%15s\n" % "{:,.2f}".format(size))
                stream.write("\t\tMin: {:,.2f}".format(min_val))
                stream.write("    Max: {:,.2f}".format(max_val))
                stream.write("    Delta: {:,.2f}\n".format(delta))
