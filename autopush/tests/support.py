from twisted.logger import ILogObserver
from zope.interface import implementer


@implementer(ILogObserver)
class TestingLogObserver(object):
    def __init__(self):
        self._events = []

    def __call__(self, event):
        self._events.append(event)

    def __len__(self):
        return len(self._events)

    def logged(self, predicate):
        """Determine if any log events satisfy the callable"""
        assert callable(predicate)
        return any(predicate(e) for e in self._events)

    def logged_ci(self, predicate):
        """Determine if any log client_infos satisfy the callable"""
        assert callable(predicate)
        return self.logged(
            lambda e: 'client_info' in e and predicate(e['client_info']))

    def logged_session(self):
        """Extract the last logged session"""
        return filter(lambda e: e["log_format"] == "Session",
                      self._events)[-1]
