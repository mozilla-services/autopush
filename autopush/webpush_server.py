"""WebPush Server

"""
from twisted.logger import Logger

from autopush.db import (  # noqa
    DatabaseManager,
)

from autopush.config import AutopushConfig  # noqa
from autopush_rs import AutopushServer  # noqa

log = Logger()

# sentinel objects
_STOP = object()


###############################################################################
# Main push server class
###############################################################################
class WebPushServer(object):
    def __init__(self, conf, db, num_threads=10):
        # type: (AutopushConfig, DatabaseManager, int) -> None
        self.conf = conf
        self.db = db
        self.db.setup_tables()
        self.num_threads = num_threads
        self.rust = AutopushServer(conf, db.message_tables)
        self.running = False

    def start(self):
        # type: () -> None
        self.running = True
        self.rust.startService()

    def stop(self):
        self.running = False
        self.rust.stopService()
