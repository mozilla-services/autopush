from cryptography.fernet import InvalidToken
from marshmallow import Schema, fields, pre_load
from twisted.internet.threads import deferToThread

from autopush.exceptions import InvalidRequest, InvalidTokenException
from autopush.utils import WebPushNotification
from autopush.web.base import threaded_validate, BaseWebHandler


class MessageSchema(Schema):
    notification = fields.Raw()

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
        return dict(notification=notif)


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
        notif = self.valid_input['notification']
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
