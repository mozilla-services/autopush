from nose.plugins import Plugin
from pympler import asizeof


_testing = False
tracked_objects = []
test_results = {}
open_objects = {}


def track_object(obj):
    # Only track if testing
    if not _testing:
        return

    obj_id = id(obj)
    if obj_id in open_objects:
        existing = open_objects[obj_id]
        tracked_objects.append((obj, asizeof.asizeof(obj)-existing))
    else:
        open_objects[obj_id] = asizeof.asizeof(obj)


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
            for obj, size in objs:
                stream.write("\t%s\t%s\n" % (obj, size))
