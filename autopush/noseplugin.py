from autobahn.twisted.websocket import WebSocketServerFactory
from nose.plugins import Plugin
from pympler import asizeof

from autopush.settings import AutopushSettings

_testing = False
tracked_objects = []
test_results = {}
open_objects = {}


def track_object(obj, msg=None):
    # Only track if testing
    sizer = asizeof.Asizer()
    sizer.exclude_types(AutopushSettings, WebSocketServerFactory)
    if not _testing:
        return

    tracked_objects.append((obj, sizer.asizeof(obj), msg))


class ObjectTracker(Plugin):  # pragma: nocover
    name = "object-tracker"

    def startTest(self, test):
        global _testing
        _testing = hasattr(test, "track_objects")

    def stopTest(self, test):
        global tracked_objects, open_objects
        if hasattr(test, "track_objects"):
            test_name = test.id()
            if tracked_objects:
                test_results[test_name] = tracked_objects

        tracked_objects = []
        open_objects = {}

    def report(self, stream):
        stream.write("\n\nObject Tracking Results\n")
        for test in sorted(test_results.keys()):
            objs = test_results[test]
            stream.write("\n%s\n" % test)
            for obj, size, msg in objs:
                if msg:
                    out = "%s%25s" % (obj, msg)
                else:
                    out = "%s%s" % (obj, " " * 25)
                stream.write("%s\t%15s\n" % (out, "{:,}".format(size)))
