"""Health Check HTTP Handler"""

import cyclone.web
from boto.dynamodb2.exceptions import InternalServerError
from twisted.internet.defer import DeferredList
from twisted.internet.threads import deferToThread

from autopush import __version__
from autopush.db import table_exists
from autopush.exceptions import MissingTableException
from autopush.web.base import BaseWebHandler


class HealthHandler(BaseWebHandler):
    """HTTP Health Handler"""

    def authenticate_peer_cert(self):
        """Skip authentication checks"""
        pass

    @cyclone.web.asynchronous
    def get(self):
        """HTTP Get

        Returns basic information about the version and how many clients are
        connected in a JSON object.

        """
        self._healthy = True
        self._health_checks = dict(
            version=__version__,
            clients=len(getattr(self.application, 'clients', ()))
        )

        dl = DeferredList([
            self._check_table(self.db.router.table),
            self._check_table(self.db.message.table, "storage")
        ])
        dl.addBoth(self._finish_response)

    def _check_table(self, table, name_over=None):
        """Checks the tables known about in DynamoDB"""
        d = deferToThread(table_exists, table.table_name, self.db.client)
        d.addCallback(self._check_success, name_over or table.table_name)
        d.addErrback(self._check_error, name_over or table.table_name)
        return d

    def _check_success(self, exists, name):
        """Verifies a Table exists"""
        if not exists:
            raise MissingTableException("Nonexistent table")
        self._health_checks[name] = {"status": "OK"}

    def _check_error(self, failure, name):
        """Returns an error, and why"""
        self._healthy = False
        fmt = failure.value.message or "Heath Exception"
        self.log.failure(format=fmt, failure=failure, name=name)

        cause = self._health_checks[name] = {"status": "NOT OK"}
        if failure.check(InternalServerError):
            cause["error"] = "Server error"
        elif failure.check(MissingTableException):
            cause["error"] = failure.getErrorMessage()
        else:
            cause["error"] = "Internal error"

    def _finish_response(self, results):
        """Returns whether the check succeeded or not"""
        if self._healthy:
            self._health_checks["status"] = "OK"
        else:
            self.set_status(503, reason=None)
            self._health_checks["status"] = "NOT OK"

        self.write(self._health_checks)
        self.finish()


class StatusHandler(BaseWebHandler):
    """HTTP Status Handler"""

    def authenticate_peer_cert(self):
        """skip authentication checks"""
        pass

    def get(self):
        """HTTP Get

        Returns that this node is alive, and the version.

        """
        self.write({
            "status": "OK",
            "version": __version__
        })


class MemUsageHandler(BaseWebHandler):
    """Spits out some memory stats.

    Should be ran on its own port, not accessible externally.

    """

    def authenticate_peer_cert(self):
        """skip authentication checks"""
        pass  # pragma: nocover

    def get(self):
        """HTTP Get

        Returns the memory stats.

        """
        from autopush.memusage import memusage

        def enabled(name):
            return self.get_argument(name, u'true').lower() != u'false'
        d = deferToThread(
            memusage,
            do_dump_rpy_heap=enabled('dump_rpy_heap'),
            do_objgraph=enabled('objgraph')
        )
        d.addCallback(self.write)
        d.addCallback(self.finish)
        d.addErrback(self._response_err)
        return d
