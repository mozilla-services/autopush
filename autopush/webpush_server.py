"""WebPush Server

"""
from threading import Thread
from uuid import UUID

import attr
from attr import (
    attrs,
    attrib,
)
from typing import (  # noqa
    Dict,
    List,
    Optional,
    Tuple
)
from twisted.logger import Logger

from autopush.db import (  # noqa
    DatabaseManager,
    Message,
)

from autopush.config import AutopushConfig  # noqa
from autopush.metrics import IMetrics  # noqa
from autopush.web.webpush import MAX_TTL
from autopush.types import JSONDict  # noqa
from autopush.utils import WebPushNotification
from autopush_rs import AutopushServer, AutopushQueue  # noqa

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


def dict_to_webpush_message(input):
    if isinstance(input, dict):
        return WebPushMessage(
            uaid=input.get("uaid"),
            timestamp=input["timestamp"],
            channelID=input["channelID"],
            ttl=input["ttl"],
            topic=input.get("topic"),
            version=input["version"],
            sortkey_timestamp=input.get("sortkey_timestamp"),
            data=input.get("data"),
            headers=input.get("headers"),
        )
    return input


@attrs(slots=True)
class WebPushMessage(object):
    """Serializable version of attributes needed for message delivery"""
    uaid = attrib()  # type: str
    timestamp = attrib()  # type: int
    channelID = attrib()  # type: str
    ttl = attrib()  # type: int
    topic = attrib()  # type: str
    version = attrib()  # type: str
    sortkey_timestamp = attrib(default=None)  # type: Optional[str]
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
            ttl=MAX_TTL if notif.ttl is None else int(notif.ttl),
            topic=notif.topic,
            **p
        )

    def to_WebPushNotification(self):
        # type: () -> WebPushNotification
        notif = WebPushNotification(
            uaid=UUID(self.uaid),
            channel_id=self.channelID,
            data=self.data,
            headers=self.headers,
            ttl=self.ttl,
            topic=self.topic,
            timestamp=self.timestamp,
            message_id=self.version,
            update_id=self.version,
            sortkey_timestamp=self.sortkey_timestamp,
        )

        # If there's no sortkey_timestamp and no topic, its legacy
        if notif.sortkey_timestamp is None and not notif.topic:
            notif.legacy = True

        return notif


###############################################################################
# Input messages off the incoming queue
###############################################################################
@attrs(slots=True)
class InputCommand(object):
    pass


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
        # type: (AutopushConfig, DatabaseManager, int) -> None
        self.conf = conf
        self.db = db
        self.db.setup_tables()
        self.num_threads = num_threads
        self.incoming = AutopushQueue()
        self.workers = []  # type: List[Thread]
        self.command_processor = CommandProcessor(conf, self.db)
        self.rust = AutopushServer(conf, db.message_tables, self.incoming)
        self.running = False

    def start(self):
        # type: () -> None
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
        for worker in self.workers:
            worker.join()

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
                    # TODO: Handle traceback better
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
        # type: (AutopushConfig, DatabaseManager) -> None
        self.conf = conf
        self.db = db
        self.migrate_user_proocessor = MigrateUserCommand(conf, db)
        self.store_messages_process = StoreMessagesUserCommand(conf, db)
        self.deserialize = dict(
            migrate_user=MigrateUser,
            store_messages=StoreMessages,
        )
        self.command_dict = dict(
            migrate_user=self.migrate_user_proocessor,
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
        log.debug(
            'command: {command} {input}',
            command=pformat(command),
            input=input
        )
        command_obj = self.deserialize[command](**input)
        response = attr.asdict(self.command_dict[command].process(command_obj))
        log.debug('response: {response}', response=response)
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


class MigrateUserCommand(ProcessorCommand):
    def process(self, command):
        # type: (MigrateUser) -> MigrateUserResponse
        # Get the current channels for this month
        message = Message(command.message_month,
                          boto_resource=self.db.resource)
        _, channels = message.all_channels(command.uaid.hex)

        # Get the current message month
        cur_month = self.db.current_msg_month
        if channels:
            # Save the current channels into this months message table
            msg_table = Message(cur_month,
                                boto_resource=self.db.resource)
            msg_table.save_channels(command.uaid.hex,
                                    channels)

        # Finally, update the route message month
        self.db.router.update_message_month(command.uaid.hex,
                                            cur_month)
        return MigrateUserResponse(message_month=cur_month)


class StoreMessagesUserCommand(ProcessorCommand):
    def process(self, command):
        # type: (StoreMessages) -> StoreMessagesResponse
        message = Message(command.message_month,
                          boto_resource=self.db.resource)
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
