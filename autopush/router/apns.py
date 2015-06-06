from twisted.python import log
import apns
import time


# https://github.com/djacobs/PyAPNs
class APNSRouter(object):
    apns = None
    messages = {}
    errors = {0: 'No error',
              1: 'Processing error',
              2: 'Missing device token',
              3: 'Missing topic',
              4: 'Missing payload',
              5: 'Invalid token size',
              6: 'Invalid topic size',
              7: 'Invalid payload size',
              8: 'Invalid token',
              10: 'Shutdown',
              255: 'Unknown',
              }

    def _connect(self):
        self.apns = apns.APNs(use_sandbox=self.config.get("sandbox", False),
                              cert_file=self.config.get("cert_file"),
                              key_file=self.config.get("key_file"),
                              enhanced=True)

    def __init__(self, config, storage):
        self.config = config
        self.default_title = config.get("default_title", "SimplePush")
        self.default_body = config.get("default_body", "New Alert")
        self.storage = storage
        self._connect()
        log.msg("Starting APNS bridge...")

    def _error(self, err):
        if err['status'] == 0:
            log.msg("Success")
            del self.messages[err['identifier']]
            return
        log.err("APNs Error encountered: %s" % self.errors[err['status']])
        if err['status'] in [1, 255]:
            log.msg("Retrying...")
            self._connect()
            resend = self.messages.get(err.get('identifier'))
            if resend is None:
                return
            self.apns.gateway_server.send_notification(resend['token'],
                                                       resend['payload'],
                                                       err['identifier'],
                                                       )
            return

    def ping(self, uaid, version, data, connectInfo):
        try:
            if connectInfo.get("type").lower() != "apns":
                return False
            token = connectInfo.get("token")
            if token is None:
                return False
            payload = apns.Payload(alert=connectInfo.get("title",
                                                         self.default_title),
                                   content_available=1,
                                   custom={"Msg": data,
                                           "Ver": version})
            current_id = int(time.time())
            self.messages[current_id] = {"token": token, "payload": payload}
            # TODO: Add listener for error handling.
            apns.gateway_server.register_response_listener(self._error)
            self.apns.gateway_server.send_notification(
                token, payload, current_id)
            # cleanup sent messages
            if len(self.messages):
                for id in self.messages.keys():
                    if id < current_id - self.config.get("expry", 10):
                        del self.messages[id]
                    else:
                        break
            return True
        except Exception, e:
            log.err("Unhandled APNs Exception: %s", e)
        return False
