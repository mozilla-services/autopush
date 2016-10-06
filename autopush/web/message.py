from cryptography.fernet import InvalidToken
from marshmallow import Schema, fields, pre_load
from twisted.internet.threads import deferToThread

from autopush.exceptions import InvalidRequest, InvalidTokenException
from autopush.utils import WebPushNotification
from autopush.web.base import threaded_validate, BaseWebHandler


class MessageSchema(Schema):
    uaid = fields.UUID()
    channel_id = fields.UUID(allow_none=True)
    topic = fields.Str(allow_none=True)
    message_id = fields.Str()

    @pre_load
    def extract_data(self, req):
        message_id = None
        if req['path_args']:
            message_id = req['path_args'][0]
        message_id = req['path_kwargs'].get(
            'message_id',
            message_id)
        if not message_id:
            raise InvalidRequest("Missing Token",
                                 status_code=400)
        try:
            notif = WebPushNotification.from_message_id(
                bytes(message_id),
                fernet=self.context['settings'].fernet,
            )
        except (InvalidToken, InvalidTokenException):
            raise InvalidRequest("Invalid message ID",
                                 status_code=400)
        return dict(uaid=notif.uaid,
                    channel_id=notif.channel_id,
                    topic=notif.topic,
                    message_id=message_id)


class MessageHandler(BaseWebHandler):
    cors_methods = "DELETE"
    cors_response_headers = ("location",)

    @threaded_validate(MessageSchema)
    def delete(self, *args, **kwargs):
        """Drops a pending message.

        The message will only be removed from DynamoDB. Messages that were
        successfully routed to a client as direct updates, but not delivered
        yet, will not be dropped.


        """
        notif = WebPushNotification(
            uaid=self.valid_input['uaid'],
            channel_id=self.valid_input['channel_id'],
            data=None,
            ttl=None,
            topic=self.valid_input['topic'],
            message_id=self.valid_input['message_id'])
        d = deferToThread(self.ap_settings.message.delete_message,
                          notif)
        d.addCallback(self._delete_completed)
        self._db_error_handling(d)
        return d

    def _delete_completed(self, *args, **kwargs):
        self.log.info(format="Message Deleted", status_code=204,
                      **self._client_info)
        self.set_status(204)
        self.finish()
