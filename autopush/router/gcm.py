"""GCM Router"""
import gcmclient
import json
from base64 import urlsafe_b64encode

from twisted.python import log
from twisted.internet.threads import deferToThread

from autopush.router.interface import RouterException, RouterResponse
from autopush.senderids import SenderIDs


class GCMRouter(object):
    """GCM Router Implementation"""
    gcm = None
    ttl = 60
    dryRun = 0
    collapseKey = "simplepush"
    creds = {}

    def __init__(self, ap_settings, router_conf):
        """Create a new GCM router and connect to GCM"""
        self.config = router_conf
        self.ttl = router_conf.get("ttl", 60)
        self.dryRun = router_conf.get("dryrun", False)
        self.collapseKey = router_conf.get("collapseKey", "simplepush")
        self.senderIDs = router_conf.get("senderIDs")
        if not self.senderIDs:
            self.senderIDs = SenderIDs(router_conf)
        try:
            senderID = self.senderIDs.choose_ID()
            self.gcm = gcmclient.GCM(senderID.get("auth"))
        except:
            raise IOError("GCM Bridge not initiated in main")
        log.msg("Starting GCM router...")

    def check_token(self, token):
        if token not in self.senderIDs.senderIDs():
            return (False, self.senderIDs.choose_ID().get('senderID'))
        return (True, token)

    def amend_msg(self, msg):
        msg["senderid"] = self.creds.get("senderID")
        return msg

    def register(self, uaid, router_data, router_token=None, *kwargs):
        """ Validate that the GCM Instance Token is in the ``router_data``"""
        if "token" not in router_data:
            raise self._error("connect info missing GCM Instance 'token'",
                              status=401)
        # Assign a senderid
        router_data["creds"] = self.creds = \
            self.senderIDs.get_ID(router_token)
        return router_data

    def route_notification(self, notification, uaid_data):
        """Start the GCM notification routing, returns a deferred"""
        router_data = uaid_data["router_data"]
        # Kick the entire notification routing off to a thread
        return deferToThread(self._route, notification, router_data)

    def _route(self, notification, router_data):
        """Blocking GCM call to route the notification"""
        data = {"chid": notification.channel_id,
                "ver": notification.version}
        # Payload data is optional.  If present, all of Content-Encoding,
        # Encryption, and Encryption/Crypto-Key are required.  If one or
        # more are missing, a 400 response is produced.
        if notification.data:
            lead = "notification with data is missing header:"
            con = notification.headers.get('content-encoding', None)
            if not con:
                raise self._error("%s Content-Encoding" % lead, 400)
            enc = notification.headers.get('encryption', None)
            if not enc:
                raise self._error("%s Encryption" % lead, 400)
            if ('crypto-key' in notification.headers and
                    'encryption-key' in notification.headers):
                raise self._error("notification with data has both"
                                  "crypto-key and encryption-key headers",
                                  400)
            if not ('crypto-key' in notification.headers or
                    'encryption-key' in notification.headers):
                raise self._error("notification with data is missing " +
                                  "key header", 400)
            if ('encryption-key' in notification.headers):
                data['enckey'] = notification.headers.get('encryption-key')
            if ('crypto-key' in notification.headers):
                data['cryptokey'] = notification.headers.get('crypto-key')
            udata = urlsafe_b64encode(notification.data)
            mdata = self.config.get('max_data', 4096)
            if len(udata) > mdata:
                raise self._error("This message is intended for a " +
                                  "constrained device and is limited " +
                                  "to 3070 bytes. Converted buffer too " +
                                  "long by %d bytes" % (len(udata) - mdata),
                                  413, errno=104)
            # TODO: if the data is longer than max_data, raise error
            data['body'] = udata
            data['con'] = con
            data['enc'] = enc

        # registration_ids are the GCM instance tokens (specified during
        # registration.
        payload = gcmclient.JSONMessage(
            registration_ids=[router_data.get("token")],
            collapse_key=self.collapseKey,
            time_to_live=self.ttl,
            dry_run=self.dryRun or "dryrun" in router_data,
            data=data,
        )
        creds = router_data.get("creds", {"senderID": "missing id"})
        try:
            self.gcm.api_key = creds["auth"]
            result = self.gcm.send(payload)
        except KeyError:
            raise self._error("Server error, missing bridge credentials " +
                              "for %s" % creds.get("senderID"), 500)
        except gcmclient.GCMAuthenticationError, e:
            raise self._error("Authentication Error: %s" % e, 500)
        except Exception, e:
            raise self._error("Unhandled exception in GCM Routing: %s" % e,
                              500)
        return self._process_reply(result)

    def _error(self, err, status, **kwargs):
        """Error handler that raises the RouterException"""
        log.err(err, **kwargs)
        return RouterException(err, status_code=status, response_body=err,
                               **kwargs)

    def _process_reply(self, reply):
        """Process GCM send reply"""
        # acks:
        #  for reg_id, msg_id in reply.success.items():
        # updates
        for old_id, new_id in reply.canonical.items():
            log.msg("GCM id changed : %s => " % old_id, new_id)
            return RouterResponse(status_code=503,
                                  response_body="Please try request again.",
                                  router_data=dict(token=new_id))
        # naks:
        # uninstall:
        for reg_id in reply.not_registered:
            log.msg("GCM no longer registered: %s" % reg_id)
            return RouterResponse(
                status_code=410,
                response_body="Endpoint requires client update",
                router_data={},
            )

        #  for reg_id, err_code in reply.failed.items():
        if len(reply.failed.items()) > 0:
            log.msg("GCM failures: %s" % json.dumps(reply.failed.items()))
            raise RouterException("GCM failure to deliver", status_code=503,
                                  response_body="Please try request later.")

        # retries:
        if reply.needs_retry():
            raise RouterException("GCM failure to deliver", status_code=503,
                                  response_body="Please try request later.")

        return RouterResponse(status_code=200, response_body="Message Sent")
