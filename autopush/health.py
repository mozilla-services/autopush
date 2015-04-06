import cyclone.web

from autopush import __version__


class StatusHandler(cyclone.web.RequestHandler):
    def get(self):
        self.write({
            "status": "OK",
            "version": __version__
        })
