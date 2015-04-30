import cyclone.web

from boto.dynamodb2.exceptions import (
    InternalServerError,
)
from twisted.internet.defer import DeferredList
from twisted.internet.threads import deferToThread
from twisted.python import log

from autopush import __version__


class MissingTableException(Exception):
    pass


class HealthHandler(cyclone.web.RequestHandler):
    @cyclone.web.asynchronous
    def get(self):
        self._healthy = True
        self._health_checks = {
            "version": __version__,
            "clients": len(self.ap_settings.clients)
        }

        dl = DeferredList([
            self._check_table(self.ap_settings.router.table),
            self._check_table(self.ap_settings.storage.table)
        ])
        dl.addBoth(self._finish_response)

    def _check_table(self, table):
        d = deferToThread(table.connection.list_tables)
        d.addCallback(self._check_success, table.table_name)
        d.addErrback(self._check_error, table.table_name)
        return d

    def _check_success(self, result, name):
        if name not in result.get("TableNames", {}):
            raise MissingTableException("Nonexistent table")
        self._health_checks[name] = {"status": "OK"}

    def _check_error(self, failure, name):
        self._healthy = False
        log.err(failure, name)

        cause = self._health_checks[name] = {"status": "NOT OK"}
        if failure.check(InternalServerError):
            cause["error"] = "Server error"
        elif failure.check(MissingTableException):
            cause["error"] = failure.getErrorMessage()
        else:
            cause["error"] = "Internal error"

    def _finish_response(self, results):
        if self._healthy:
            self._health_checks["status"] = "OK"
        else:
            self.set_status(503)
            self._health_checks["status"] = "NOT OK"

        self.write(self._health_checks)
        self.finish()


class StatusHandler(cyclone.web.RequestHandler):
    def get(self):
        self.write({
            "status": "OK",
            "version": __version__
        })
