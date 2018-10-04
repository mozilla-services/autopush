"""DockerFlow endpoints"""

import cyclone.web

from twisted.internet.threads import deferToThread
from autopush.web.base import BaseWebHandler


class VersionHandler(BaseWebHandler):

    def _get_version(self):
        self.set_header("Content-Type", "application/json")
        try:
            with open("version.json") as vers:
                self.write(vers.read())
        except IOError as ex:
            # Trap the exception here because it can be converted to
            # a generic AssertionError failure, and context gets lost.
            self.log.error(
                "Could not display version.json file content {}".format(
                    ex
                ))
            raise

    def _error(self, failure):
        failure.trap(AssertionError, IOError)
        self.set_status(500)
        self.write("")

    def get(self):
        d = deferToThread(self._get_version)
        d.addBoth(self.finish)
        d.addErrback(self._error)
        return d

    def authenticate_peer_cert(self):
        pass


class LBHeartbeatHandler(BaseWebHandler):

    @cyclone.web.asynchronous
    def get(self):
        self.write("")
        self.finish()

    def authenticate_peer_cert(self):
        pass
