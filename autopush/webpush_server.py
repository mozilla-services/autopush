"""WebPush Server

"""
import atexit
from threading import Thread
from uuid import UUID, uuid4

import attr
from attr import (
    attrs,
    attrib,
)
from boto.dynamodb2.exceptions import ItemNotFound
from typing import Dict, List, Optional  # noqa
from twisted.logger import Logger

from autopush.db import (  # noqa
    DatabaseManager,
    has_connected_this_month,
    generate_last_connect,
)
from autopush.config import AutopushConfig  # noqa
from autopush.types import JSONDict  # noqa
from autopush.utils import WebPushNotification
from autopush.websocket import USER_RECORD_VERSION
from autopush_rs import AutopushCall, AutopushServer, AutopushQueue  # noqa

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


###############################################################################
# Input messages off the incoming queue
###############################################################################
@attrs(slots=True)
class InputCommand(object):
    pass


@attrs(slots=True)
class Hello(InputCommand):
    connected_at = attrib()  # type: int
    uaid = attrib(default=None, convert=uaid_from_str)  # type: Optional[UUID]


@attrs(slots=True)
class CheckStorage(InputCommand):
    uaid = attrib(convert=uaid_from_str)  # type: UUID
    message_month = attrib()  # type: str
    include_topic = attrib()  # type: bool
    timestamp = attrib(default=None)  # type: Optional[int]


@attrs(slots=True)
class IncStoragePosition(InputCommand):
    uaid = attrib(convert=uaid_from_str)  # type: UUID
    message_month = attrib()  # type: str
    timestamp = attrib()  # type: int


###############################################################################
# Output messages serialized to the outgoing queue
###############################################################################
@attrs(slots=True)
class OutputCommand(object):
    pass


@attrs(slots=True)
class HelloResponse(OutputCommand):
    uaid = attrib()  # type: Optional[str]
    message_month = attrib()  # type: str
    reset_uaid = attrib()  # type: bool
    rotate_message_table = attrib(default=False)  # type: bool


@attrs(slots=True)
class WebPushNotificationResponse(object):
    """Serializable version of attributes needed for message delivery"""
    uaid = attrib()  # type: str
    timestamp = attrib()  # type: int
    sortkey_timestamp = attrib()  # type: Optional[int]
    channel_id = attrib()  # type: str
    ttl = attrib()  # type: int
    topic = attrib()  # type: str
    version = attrib()  # type: str
    data = attrib(default=None)  # type: Optional[str]
    headers = attrib(default=None)  # type: Optional[JSONDict]

    @classmethod
    def from_WebPushNotification(cls, notif):
        # type: (WebPushNotification) -> WebPushNotificationResponse
        p = notif.websocket_format()
        del p["messageType"]
        p["channel_id"] = p.pop("channelID")
        return cls(
            uaid=notif.uaid.hex,
            timestamp=notif.timestamp,
            sortkey_timestamp=notif.sortkey_timestamp,
            ttl=notif.ttl,
            topic=notif.topic,
            **p
        )

    def to_WebPushNotification(self):
        # type: () -> WebPushNotification
        return WebPushNotification(
            uaid=UUID(self.uaid),
            channel_id=self.channel_id,
            data=self.data,
            headers=self.headers,
            ttl=self.ttl,
            topic=self.topic,
            timestamp=self.timestamp,
            message_id=self.version,
        )


@attrs(slots=True)
class CheckStorageResponse(OutputCommand):
    include_topic = attrib()  # type: bool
    messages = attrib(
        default=attr.Factory(list)
    )  # type: List[WebPushNotificationResponse]
    timestamp = attrib(default=None)  # type: Optional[int]


@attrs(slots=True)
class IncStoragePositionResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


###############################################################################
# Main push server class
###############################################################################
class WebPushServer(object):
    def __init__(self, conf, db):
        # type: (AutopushConfig) -> WebPushServer
        self.conf = conf
        self.db = db
        self.db.setup_tables()
        self.metrics = self.db.metrics
        self.incoming = AutopushQueue()
        self.workers = []  # type: List[Thread]
        self.command_processor = CommandProcessor(conf, self.db)
        self.rust = AutopushServer(conf, self.incoming)

    def start(self, num_threads=10):
        # type: (int) -> None
        for _ in range(num_threads):
            self.workers.append(
                self._create_thread_worker(
                    processor=self.command_processor,
                    input_queue=self.incoming,
                )
            )
        self.rust.startService()
        atexit.register(self.stop)

    def stop(self):
        self.rust.stopService()

        while self.workers:
            self.workers.pop().join()

    def _create_thread_worker(self, processor, input_queue):
        # type: (CommandProcessor, AutopushQueue) -> Thread
        def _thread_worker():
            while True:
                call = input_queue.recv()
                try:
                    if call is None:
                        break
                    command = call.json()
                    result = processor.process_message(command)
                    call.complete(result)
                except Exception as exc:
                    log.error("Exception in worker queue thread")
                    call.complete(dict(
                        error=True,
                        error_msg=str(exc),
                    ))
        return self.spawn(_thread_worker)

    def spawn(self, func, *args, **kwargs):
        t = Thread(target=func, args=args, kwargs=kwargs)
        t.daemon = True
        t.start()
        return t


class CommandProcessor(object):
    def __init__(self, conf, db):
        # type: (AutopushConfig, DatabaseManager) -> CommandProcessor
        self.conf = conf
        self.db = db
        self.hello_processor = HelloCommand(conf, db)
        self.check_storage_processor = CheckStorageCommand(conf, db)
        self.inc_storage_processor = IncrementStorageCommand(conf, db)
        self.deserialize = dict(
            hello=Hello,
            check_storage=CheckStorage,
            inc_storage_position=IncStoragePosition
        )
        self.command_dict = dict(
            hello=self.hello_processor,
            check_storage=self.check_storage_processor,
            inc_storage_position=self.inc_storage_processor,
        )  # type: Dict[str, ProcessorCommand]

    def process_message(self, input):
        # type: (JSONDict) -> JSONDict
        """Process incoming message from the Rust server"""
        command = input.pop("command", None)  # type: str
        if command not in self.command_dict:
            log.critical("No command present: %s", command)
            return dict(
                error=True,
                error_msg="Command not found",
            )

        command_obj = self.deserialize[command](**input)
        return attr.asdict(self.command_dict[command].process(command_obj))


class ProcessorCommand(object):
    """Parent class for processor commands"""
    def process(self, command):
        raise NotImplementedError()


class HelloCommand(ProcessorCommand):
    def __init__(self, conf, db):
        # type: (AutopushConfig, DatabaseManager) -> HelloCommand
        self.conf = conf
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
        uaid = user_item["uaid"]  # type: str
        success, _ = self.db.router.register_user(user_item)
        if not success:
            # User has already connected more recently elsewhere
            return HelloResponse(uaid=None, **flags)

        return HelloResponse(uaid=uaid, **flags)

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
        record["node_id"] = self.conf.router_url
        record["connected_at"] = hello.connected_at
        return record, flags

    def create_user(self, hello):
        # type: (Hello) -> JSONDict
        return dict(
            uaid=uuid4().hex,
            node_id=self.conf.router_url,
            connected_at=hello.connected_at,
            router_type="webpush",
            last_connect=generate_last_connect(),
            record_version=USER_RECORD_VERSION,
            current_month=self.db.current_month,
        )


class CheckStorageCommand(ProcessorCommand):
    def __init__(self, conf, db):
        # type: (AutopushConfig, DatabaseManager) -> CheckStorageCommand
        self.conf = conf
        self.db = db

    def process(self, command):
        # type: (CheckStorage) -> CheckStorageResponse

        # First, determine if there's any messages to retrieve
        timestamp, messages, include_topic = self._check_storage(command)
        return CheckStorageResponse(
            timestamp=timestamp,
            messages=messages,
            include_topic=include_topic,
        )

    def _check_storage(self, command):
        timestamp = None
        messages = []
        message = self.db.message_tables[command.message_month]
        if command.include_topic:
            timestamp, messages = message.fetch_messages(
                uaid=command.uaid, limit=11,
            )

            # If we have topic messages, return them immediately
            messages = [WebPushNotificationResponse.from_WebPushNotification(m)
                        for m in messages]
            if messages:
                return timestamp, messages, True

            # No messages, update the command to include the last timestamp
            # that was ack'd
            command.timestamp = timestamp

        if not messages or command.timestamp:
            timestamp, messages = message.fetch_timestamp_messages(
                uaid=command.uaid,
                timestamp=command.timestamp,
            )
        messages = [WebPushNotificationResponse.from_WebPushNotification(m)
                    for m in messages]
        return timestamp, messages, False


class IncrementStorageCommand(ProcessorCommand):
    def __init__(self, conf, db):
        # type: (AutopushConfig, DatabaseManager) -> CheckStorageCommand
        self.conf = conf
        self.db = db

    def process(self, command):
        # type: (IncStoragePosition) -> IncStoragePositionResponse
        message = self.db.message_tables[command.message_month]
        message.update_last_message_read(command.uaid, command.timestamp)
        return IncStoragePositionResponse()
