"""WebPush Server

"""
from threading import Thread
from uuid import UUID, uuid4

import attr
from attr import (
    attrs,
    attrib,
)
from boto.dynamodb2.exceptions import ItemNotFound
from boto.exception import JSONResponseError
from typing import Dict, List, Optional  # noqa
from twisted.logger import Logger

from autopush.db import (  # noqa
    DatabaseManager,
    has_connected_this_month,
    hasher,
    generate_last_connect,
)
from autopush.config import AutopushConfig  # noqa
from autopush.metrics import IMetrics  # noqa
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


@attrs(slots=True)
class WebPushMessage(object):
    """Serializable version of attributes needed for message delivery"""
    uaid = attrib()  # type: str
    timestamp = attrib()  # type: int
    channelID = attrib()  # type: str
    ttl = attrib()  # type: int
    topic = attrib()  # type: str
    version = attrib()  # type: str
    sortkey_timestamp = attrib(default=None)  # type: Optional[int]
    data = attrib(default=None)  # type: Optional[str]
    headers = attrib(default=None)  # type: Optional[JSONDict]

    @classmethod
    def from_WebPushNotification(cls, notif):
        # type: (WebPushNotification) -> WebPushMessage
        p = notif.websocket_format()
        del p["messageType"]
        return cls(
            uaid=notif.uaid.hex,
            timestamp=int(notif.timestamp),
            sortkey_timestamp=notif.sortkey_timestamp,
            ttl=int(notif.ttl) if notif.ttl else notif.ttl,
            topic=notif.topic,
            **p
        )

    def to_WebPushNotification(self):
        # type: () -> WebPushNotification
        return WebPushNotification(
            uaid=UUID(self.uaid),
            channel_id=self.channelID,
            data=self.data,
            headers=self.headers,
            ttl=self.ttl,
            topic=self.topic,
            timestamp=self.timestamp,
            message_id=self.version,
            update_id=self.version,
        )


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


@attrs(slots=True)
class DeleteMessage(InputCommand):
    message_month = attrib()  # type: str
    message = attrib()  # type: WebPushMessage


@attrs(slots=True)
class DropUser(InputCommand):
    uaid = attrib(convert=uaid_from_str)  # type: UUID


@attrs(slots=True)
class MigrateUser(InputCommand):
    uaid = attrib(convert=uaid_from_str)  # type: UUID
    message_month = attrib()  # type: str


@attrs(slots=True)
class StoreMessages(InputCommand):
    message_month = attrib()  # type: str
    messages = attrib(
        default=attr.Factory(list)
    )  # type: List[WebPushMessage]


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
class CheckStorageResponse(OutputCommand):
    include_topic = attrib()  # type: bool
    messages = attrib(
        default=attr.Factory(list)
    )  # type: List[WebPushMessage]
    timestamp = attrib(default=None)  # type: Optional[int]


@attrs(slots=True)
class IncStoragePositionResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


@attrs(slots=True)
class DeleteMessageResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


@attrs(slots=True)
class DropUserResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


@attrs(slots=True)
class MigrateUserResponse(OutputCommand):
    message_month = attrib()  # type: str


@attrs(slots=True)
class StoreMessagesResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


###############################################################################
# Main push server class
###############################################################################
class WebPushServer(object):
    def __init__(self, conf, db, num_threads=10):
        # type: (AutopushConfig, DatabaseManager) -> WebPushServer
        self.conf = conf
        self.db = db
        self.db.setup_tables()
        self.num_threads = num_threads
        self.metrics = self.db.metrics
        self.incoming = AutopushQueue()
        self.workers = []  # type: List[Thread]
        self.command_processor = CommandProcessor(conf, self.db)
        self.rust = AutopushServer(conf, self.incoming)
        self.running = False

    def run(self):
        self.start()
        for worker in self.workers:
            worker.join()

    def start(self):
        # type: (int) -> None
        self.running = True
        for _ in range(self.num_threads):
            self.workers.append(
                self._create_thread_worker(
                    processor=self.command_processor,
                    input_queue=self.incoming,
                )
            )
        self.rust.startService()

    def stop(self):
        self.running = False
        self.rust.stopService()

    def _create_thread_worker(self, processor, input_queue):
        # type: (CommandProcessor, AutopushQueue) -> Thread
        def _thread_worker():
            while self.running:
                call = input_queue.recv()
                try:
                    if call is None:
                        break
                    command = call.json()
                    result = processor.process_message(command)
                    call.complete(result)
                except Exception as exc:
                    # XXX:
                    import traceback
                    traceback.print_exc()
                    log.error("Exception in worker queue thread")
                    call.complete(dict(
                        error=True,
                        error_msg=str(exc),
                    ))
        return self.spawn(_thread_worker)

    def spawn(self, func, *args, **kwargs):
        t = Thread(target=func, args=args, kwargs=kwargs)
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
        self.delete_message_processor = DeleteMessageCommand(conf, db)
        self.drop_user_processor = DropUserCommand(conf, db)
        self.migrate_user_proocessor = MigrateUserCommand(conf, db)
        self.register_process = RegisterCommand(conf, db)
        self.unregister_process = UnregisterCommand(conf, db)
        self.store_messages_process = StoreMessagesUserCommand(conf, db)
        self.deserialize = dict(
            hello=Hello,
            check_storage=CheckStorage,
            inc_storage_position=IncStoragePosition,
            delete_message=DeleteMessage,
            drop_user=DropUser,
            migrate_user=MigrateUser,
            register=Register,
            unregister=Unregister,
            store_messages=StoreMessages,
        )
        self.command_dict = dict(
            hello=self.hello_processor,
            check_storage=self.check_storage_processor,
            inc_storage_position=self.inc_storage_processor,
            delete_message=self.delete_message_processor,
            drop_user=self.drop_user_processor,
            migrate_user=self.migrate_user_proocessor,
            register=self.register_process,
            unregister=self.unregister_process,
            store_messages=self.store_messages_process,
        )  # type: Dict[str, ProcessorCommand]

    def process_message(self, input):
        # type: (JSONDict) -> JSONDict
        """Process incoming message from the Rust server"""
        command = input.pop("command", None)  # type: str
        if command not in self.command_dict:
            log.critical("No command present: %s" % command)
            return dict(
                error=True,
                error_msg="Command not found",
            )
        from pprint import pformat
        log.info('command: %r %r' % (pformat(command), input))
        command_obj = self.deserialize[command](**input)
        response = attr.asdict(self.command_dict[command].process(command_obj))
        log.info('response: %s' % response)
        return response


class ProcessorCommand(object):
    """Parent class for processor commands"""
    def __init__(self, conf, db):
        # type: (AutopushConfig, DatabaseManager) -> None
        self.conf = conf
        self.db = db

    @property
    def metrics(self):
        # type: () -> IMetrics
        return self.db.metrics

    def process(self, command):
        raise NotImplementedError()


class HelloCommand(ProcessorCommand):
    def process(self, hello):
        # type: (Hello) -> HelloResponse
        user_item = None
        # XXX:
        flags = dict(
            message_month=self.db.current_msg_month,
            reset_uaid=False
        )
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
        flags["message_month"] = record["current_month"]
        if record["current_month"] != self.db.current_msg_month:
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
            current_month=self.db.current_msg_month,
        )


class CheckStorageCommand(ProcessorCommand):
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
            messages = [WebPushMessage.from_WebPushNotification(m)
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
        messages = [WebPushMessage.from_WebPushNotification(m)
                    for m in messages]
        return timestamp, messages, False


class IncrementStorageCommand(ProcessorCommand):
    def process(self, command):
        # type: (IncStoragePosition) -> IncStoragePositionResponse
        message = self.db.message_tables[command.message_month]
        message.update_last_message_read(command.uaid, command.timestamp)
        return IncStoragePositionResponse()


class DeleteMessageCommand(ProcessorCommand):
    def process(self, command):
        # type: (DeleteMessage) -> DeleteMessageResponse
        notif = command.message.to_WebPushNotification()
        message = self.db.message_tables[command.message_month]
        message.delete_message(notif)
        return DeleteMessageResponse()


class DropUserCommand(ProcessorCommand):
    def process(self, command):
        # type: (DropUser) -> DropUserResponse
        self.db.router.drop_user(command.uaid.hex)
        return DropUserResponse()


class MigrateUserCommand(ProcessorCommand):
    def process(self, command):
        # type: (MigrateUser) -> MigrateUserResponse
        # Get the current channels for this month
        message = self.db.message_tables[command.message_month]
        _, channels = message.all_channels(command.uaid.hex)

        # Get the current message month
        cur_month = self.db.current_msg_month
        if channels:
            # Save the current channels into this months message table
            msg_table = self.db.message_tables[cur_month]
            msg_table.save_channels(command.uaid.hex, channels)

        # Finally, update the route message month
        self.db.router.update_message_month(command.uaid.hex, cur_month)
        return MigrateUserResponse(message_month=cur_month)


class StoreMessagesUserCommand(ProcessorCommand):
    def process(self, command):
        # type: (StoreMessages) -> StoreMessagesResponse
        message = self.db.message_tables[command.message_month]
        for m in command.messages:
            if "topic" not in m:
                m["topic"] = None
            notif = WebPushMessage(**m).to_WebPushNotification()
            message.store_message(notif)
        return StoreMessagesResponse()


def _validate_chid(chid):
    # type: (str) -> Tuple[bool, Optional[str]]
    """Ensure valid channel id format for register/unregister"""
    try:
        result = UUID(chid)
    except ValueError:
        return False, "Invalid UUID specified"
    if chid != str(result):
        return False, "Bad UUID format, use lower case, dashed format"
    return True, None


@attrs(slots=True)
class Register(InputCommand):
    channel_id = attrib()  # type: str
    uaid = attrib(convert=uaid_from_str)  # type: Optional[UUID]
    message_month = attrib()  # type: str
    key = attrib(default=None)  # type: str


@attrs(slots=True)
class RegisterResponse(OutputCommand):
    endpoint = attrib()  # type: str


@attrs(slots=True)
class RegisterErrorResponse(OutputCommand):
    error_msg = attrib()  # type: str
    error = attrib(default=True)  # type: bool
    status = attrib(default=401)  # type: int


class RegisterCommand(ProcessorCommand):

    def process(self, command):
        # type: (Register) -> Union[RegisterResponse, RegisterErrorResponse]
        valid, msg = _validate_chid(command.channel_id)
        if not valid:
            return RegisterErrorResponse(error_msg=msg)
        # XXX: pauseProducing

        endpoint = self.conf.make_endpoint(
            command.uaid.hex,
            command.channel_id,
            command.key
        )
        message = self.db.message_tables[command.message_month]
        try:
            message.register_channel(command.uaid.hex, command.channel_id)
        except JSONResponseError:
            return RegisterErrorResponse(error_msg="overloaded", status=503)
        # XXX: resumeProducing

        self.metrics.increment('ua.command.register')
        # XXX: user/raw_agent?
        log.info(
            "Register",
            channel_id=command.channel_id,
            endpoint=endpoint,
            uaid_hash=hasher(command.uaid.hex),
        )
        return RegisterResponse(endpoint=endpoint)


@attrs(slots=True)
class Unregister(InputCommand):
    channel_id = attrib()  # type: str
    uaid = attrib(convert=uaid_from_str)  # type: Optional[UUID]
    message_month = attrib()  # type: str
    code = attrib(default=None)  # type: int


@attrs(slots=True)
class UnregisterResponse(OutputCommand):
    success = attrib(default=True)  # type: bool


@attrs(slots=True)
class UnregisterErrorResponse(OutputCommand):
    error_msg = attrib()  # type: str
    error = attrib(default=True)  # type: bool
    status = attrib(default=401)  # type: int


class UnregisterCommand(ProcessorCommand):

    def process(self,
                command  # type: Unregister
                ):
        # type: (...) -> Union[UnregisterResponse, UnregisterErrorResponse]
        valid, msg = _validate_chid(command.channel_id)
        if not valid:
            return UnregisterErrorResponse(error_msg=msg)

        message = self.db.message_tables[command.message_month]
        # XXX: JSONResponseError not handled (no force_retry)
        message.unregister_channel(command.uaid.hex, command.channel_id)

        # XXX: Clear out any existing tracked messages for this
        # channel

        self.metrics.increment('ua.command.unregister')
        # XXX: user/raw_agent?
        log.info(
            "Unregister",
            channel_id=command.channel_id,
            uaid_hash=hasher(command.uaid.hex),
            **dict(code=command.code) if command.code else {}
        )
        return UnregisterResponse()
