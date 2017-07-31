"""WebPush Server

"""
import Queue
import atexit
from threading import Thread
from uuid import UUID, uuid4

from attr import (
    attrs,
    attrib,
)
from boto.dynamodb2.exceptions import ItemNotFound
from typing import List, Optional  # noqa
from twisted.logger import Logger

from autopush.db import (  # noqa
    DatabaseManager,
    has_connected_this_month,
    generate_last_connect,
)
from autopush.settings import AutopushSettings  # noqa
from autopush.types import JSONDict  # noqa
from autopush.websocket import USER_RECORD_VERSION


log = Logger()

# sentinel objects
_STOP = object()


# Conversion functions
def uaid_from_str(input):
    # type: (Optional[str]) -> Optional[UUID]
    """Parse a uaid and verify the raw input matches the hex version (no
    dashes)"""
    try:
        uuid = UUID(input)
        if uuid.hex != input:
            return None
        return uuid
    except (TypeError, ValueError):
        return None


# Input messages off the incoming queue
@attrs(slots=True)
class InputCommand(object):
    message_id = attrib()  # type: str


@attrs(slots=True)
class Hello(InputCommand):
    connected_at = attrib()  # type: int
    uaid = attrib(default=None, convert=uaid_from_str)  # type: Optional[UUID]


# Output messages serialized to the outgoing queue
@attrs(slots=True)
class OutputCommand(object):
    message_id = attrib()  # type: str


@attrs(slots=True)
class HelloResponse(OutputCommand):
    uaid = attrib(convert=uaid_from_str)  # type: Optional[UUID]
    message_month = attrib()  # type: str
    reset_uaid = attrib()  # type: bool
    rotate_message_table = attrib(default=False)  # type: bool


class WebPushServer(object):
    def __init__(self, settings):
        # type: (AutopushSettings) -> WebPushServer
        self.settings = settings
        self.db = DatabaseManager.from_settings(settings)
        self.metrics = self.db.metrics
        self.incoming = Queue.Queue()
        self.outgoing = Queue.Queue()
        self.workers = []  # type: List[Thread]
        self.command_processor = CommandProcessor(settings, self.db)
        # Setup the Rust server with its config, etc.

    def start(self, num_threads=10):
        # type: (int) -> None
        for _ in range(num_threads):
            self.workers.append(
                self._create_thread_worker(
                    processor=self.command_processor,
                    input_queue=self.incoming,
                    output_queue=self.outgoing,
                )
            )

        # Start the Rust server, give it references to our queues
        atexit.register(self.stop)

    def stop(self):
        for queue in (self.incoming, self.outgoing):
            queue.put(_STOP)

        while self.workers:
            self.workers.pop().join()

    def _create_thread_worker(self, processor, input_queue, output_queue):
        # type: (CommandProcessor, Queue.Queue, Queue.Queue) -> Thread
        def _thread_worker():
            while True:
                try:
                    command = input_queue.get()
                    try:
                        if command is _STOP:
                            break
                        result = processor.process_message(command)
                        if result:
                            output_queue.put(result)
                    except Exception:
                        log.error("Exception in worker queue thread")
                    finally:
                        input_queue.task_done()
                except Queue.Empty:
                    continue
        return self.spawn(_thread_worker)

    def spawn(self, func, *args, **kwargs):
        t = Thread(target=func, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()
        return t


class CommandProcessor(object):
    def __init__(self, settings, db):
        # type: (AutopushSettings, DatabaseManager) -> CommandProcessor
        self.settings = settings
        self.db = db
        self.hello_processor = HelloCommand(settings=settings, db=db)
        self.deserialize = dict(
            hello=self.hello_processor,
        )
        self.command_dict = dict(
            hello=HelloCommand,
        )

    def process_message(self, input):
        # type: (JSONDict) -> JSONDict
        """Process incoming message from the Rust server"""
        command = input.pop("command", None)  # type: str
        if command not in self.command_dict:
            log.critical("No command present: %s", command)
            return None

        command_obj = self.deserialize[command](**input)
        return self.command_dict[command].process(command_obj).asdict()


class HelloCommand(object):
    def __init__(self, settings, db):
        # type: (AutopushSettings, DatabaseManager) -> HelloCommand
        self.settings = settings
        self.db = db

    def process(self, hello):
        # type: (Hello) -> HelloResponse
        user_item = None
        flags = {}
        if hello.uaid:
            user_item, flags = self.lookup_user(hello)

        if not user_item:
            user_item = self.create_user(hello)

        # Save the UAID as register_user removes it
        uaid = user_item["uaid"]
        success, _ = self.db.router.register_user(user_item)
        if not success:
            # User has already connected more recently elsewhere
            return HelloResponse(
                message_id=hello.message_id,
                uaid=None,
                **flags
            )

        return HelloResponse(
            message_id=hello.message_id,
            uaid=uaid,
            **flags
        )

    def lookup_user(self, hello):
        # type: (Hello) -> (Optional[JSONDict], JSONDict)
        flags = dict(
            message_month=None,
            rotate_message_table=False,
            reset_uaid=False,
        )
        uaid = hello.uaid.hex
        try:
            record = self.db.router.get_uaid(uaid)
        except ItemNotFound:
            return None, flags

        # All records must have a router_type and connected_at, in some odd
        # cases a record exists for some users that doesn't
        if "router_type" not in record or "connected_at" not in record:
            self.db.router.drop_user(uaid)
            return None, flags

        # Current month must exist and be a valid prior month
        if ("current_month" not in record) or record["current_month"] \
                not in self.db.message_tables:
            self.db.router.drop_user(uaid)
            return None, flags

        # Determine if message table rotation is needed
        if record["current_month"] != self.db.current_msg_month:
            flags["message_month"] = record["current_month"]
            flags["rotate_message_table"] = True

        # Include and update last_connect if needed, otherwise exclude
        if has_connected_this_month(record):
            del record["last_connect"]
        else:
            record["last_connect"] = generate_last_connect()

        # Determine if this is missing a record version
        if ("record_version" not in record or
                int(record["record_version"]) < USER_RECORD_VERSION):
            flags["reset_uaid"] = True

        # Update the node_id, connected_at for this node/connected_at
        record["node_id"] = self.settings.router_url
        record["connected_at"] = hello.connected_at
        return record, flags

    def create_user(self, hello):
        # type: (Hello) -> JSONDict
        return dict(
            uaid=uuid4().hex,
            node_id=self.settings.router_url,
            connected_at=hello.connected_at,
            router_type="webpush",
            last_connect=generate_last_connect(),
            record_version=USER_RECORD_VERSION,
            current_month=self.db.current_month,
        )
