import json
import time
import urlparse
import uuid

import cyclone.web

from boto.dynamodb2.exceptions import (
    ProvisionedThroughputExceededException,
)
from cryptography.fernet import InvalidToken
from twisted.internet.threads import deferToThread
from twisted.python import log


def MakeEndPoint(fernet, endpoint_url, uaid, chid):
    """ Create an endpoint (used both by websocket handler and
    the /register endpoint """
    token = fernet.encrypt((uaid + ":" + chid).encode('utf8'))
    return endpoint_url + "/push/" + token


class EndpointHandler(cyclone.web.RequestHandler):
    def initialize(self):
        self.metrics = self.ap_settings.metrics

    def _load_params(self):
        # If there's a request body, parse it out
        version = data = None
        if len(self.request.body) > 0:
            body_args = urlparse.parse_qs(self.request.body,
                                          keep_blank_values=True)
            version = body_args.get("version")
            data = body_args.get("data")
        else:
            version = self.request.arguments.get("version")
            data = self.request.arguments.get("data")

        # These come out as lists, unlist them
        if version is not None:
            try:
                version = int(version[0])
            except ValueError:
                version = None
        if data is not None:
            data = data[0]

        if version is None or version < 1:
            version = int(time.time())

        self.version = version
        self.data = data

    def options(self, token):
        self._addCors()

    def head(self, token):
        self._addCors()

    @cyclone.web.asynchronous
    def put(self, token):
        self.start_time = time.time()
        fernet = self.ap_settings.fernet

        self._load_params()
        self._addCors()
        if self.data and len(self.data) > self.ap_settings.max_data:
            self.set_status(401)
            self.write("Data too large")
            return self.finish()

        d = deferToThread(fernet.decrypt, token.encode('utf8'))
        d.addCallback(self._process_token)
        d.addErrback(self._bad_token).addErrback(self._error_response)

    def _addCors(self):
        if self.ap_settings.cors:
            self.set_header("Access-Control-Request-Method", "*")

    def _process_token(self, result):
        self.uaid, self.chid = result.split(":")

        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._process_uaid)
        d.addErrback(self._handle_overload).addErrback(self._error_response)

    def _bad_token(self, failure):
        failure.trap(InvalidToken)
        self.set_status(401)
        self.write("Invalid token")
        self.finish()

    def _handle_overload(self, failure):
        failure.trap(ProvisionedThroughputExceededException)
        self.set_status(503)
        self.write("Server busy, try later")
        self.finish()

    def _error_response(self, failure):
        log.err(failure)
        self.set_status(500)
        self.write("Error processing request")
        self.finish()

    def _process_uaid(self, result):
        """Process the result of the AWS call"""
        if not result:
            self.set_status(404)
            self.write("Invalid")
            return self.finish()

        # Is there a proprietary ping associated with this uaid?
        pping = result.get("proprietary_ping")
        if pping is not None:
            d = deferToThread(
                self.pinger.ping,
                self.uaid,
                self.version,
                self.data,
                pping)
            d.addCallback(self._process_pping, result)
            d.addErrback(self._error_response)
            return
        self._process_route(result)

    def _process_pping(self, result, routeinfo):
        if not result:
            log.msg("proprietary ping failed, falling back to routing")
            return self._process_route(routeinfo)
        # Ping handoff succeeded, no further action required
        self.metrics.increment("router.pping.hit")
        # Since we're handing off, return 202
        self.set_status(202)
        self.write("Success")
        self.finish()

    def _process_route(self, routeinfo):
        # Determine if they're connected at the moment

        # Indicator if we got a node_id, but the node won't handle
        # delivery at this moment later.
        self.client_check = False

        if routeinfo.get("node_id"):
            # Attempt a delivery if they are connected
            payload = json.dumps([{"channelID": self.chid,
                                   "version": self.version,
                                   "data": self.data}])
            d = deferToThread(
                self.ap_settings.requests.put,
                routeinfo.get("node_id") + "/push/" + self.uaid,
                data=payload
            )
            d.addCallback(self._process_routing, routeinfo)
            d.addErrback(self._error_response)
        else:
            self._save_notification()

    def _process_routing(self, result, item):
        node_id = item.get("node_id")
        if result.status_code == 200:
            # Success, return!
            self.metrics.increment("router.broadcast.hit")
            time_diff = time.time() - self.start_time
            self.metrics.timing("updates.handled", duration=time_diff)
            self.write("Success")
            #since we're handing off, return 202
            self.set_status(202)
            return self.finish()
        elif result.status_code == 404:
            # Conditionally delete the node_id
            d = deferToThread(self.ap_settings.router.clear_node, item)
            d.addCallback(self._process_node_delete)
            d.addErrback(self._handle_overload)
            d.addErrback(self._error_response)
            return

        # Client was busy, remember to tell it to check
        self.client_check = result.status_code == 503
        self._save_notification(node_id)

    def _process_node_delete(self, result):
        if not result:
            # Client hopped, punt this request so app-server can
            # try again and get luckier
            self.set_status(503)
            self.write("Server is busy")
            self.finish()
        else:
            # Delete was ok, proceed to save the notification
            self._save_notification()

    def _save_notification(self, node_id=None):
        """Save the notification"""
        d = deferToThread(self.ap_settings.storage.save_notification,
                          uaid=self.uaid, chid=self.chid, version=self.version)
        d.addCallback(self._process_save, node_id)
        d.addErrback(self._handle_overload).addErrback(self._error_response)

    def _process_save(self, result, node_id=None):
        if self.client_check:
            # If we already know where the client was connected...
            d = deferToThread(self.ap_settings.requests.put,
                              node_id + "/notif/" + self.uaid)
            d.addCallback(self._process_notif, node_id)
            d.addErrback(self._error_response)
        else:
            # Saved the notification, check for if the client is somewhere
            # now
            d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
            d.addCallback(self._process_jumped_client)
            d.addErrback(self._handle_overload)
            d.addErrback(self._error_response)

    def _process_notif(self, result, node_id=None):
        """Process the result of a requests.PUT to a Connection Node's
        /notif/ handler"""
        if result.status_code != 404:
            # Client was notified fine, we're done
            self._finish_missed_store()
            return

        # Client jumped, if they reconnected somewhere, try one more time
        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._process_jumped_client)
        d.addErrback(self._handle_overload).addErrback(self._error_response)

    def _process_jumped_client(self, result):
        if not result:
            # Client got deleted too? bummer.
            self.set_status(404)
            self.write("Invalid")
            return self.finish()

        node_id = result.get("node_id")
        if not node_id:
            return self._finish_missed_store()

        d = deferToThread(self.ap_settings.requests.put,
                          node_id + "/notif/" + self.uaid)
        # No check on response here, because if they jumped since we
        # got this they'll definitely get the stored notification
        # We ignore errors here too, as that's a hell of an edge case
        d.addBoth(self._finish_missed_store)

    def _finish_missed_store(self, result=None):
        self.metrics.increment("router.broadcast.miss")
        self.write("Success")
        self.finish()

    def write_error(self, code, exception=None):
        """ Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.) """
        self.set_status(code)
        if exception is not None:
            log.err(exception)
        self.finish()


class RegistrationHandler(cyclone.web.RequestHandler):

    def _error_response(self, failure):
        log.err(failure)
        self.set_status(500)
        self.write("Error processing request")
        self.finish()

    def _load_params(self):
        tags = {'chid': 'channelid',
                'conn': 'connect',
                }
        chid = conn = None
        if len(self.request.body) > 0:
            body = urlparse.parse_qs(self.request.body, keep_blank_values=True)
            chid = body.get(tags['chid'], [None])[0]
            conn = body.get(tags['conn'], [None])[0]
        if chid is None:
            chid = self.request.arguments.get(tags['chid'], [None])[0]
        if conn is None:
            conn = self.request.arguments.get(tags['conn'], [None])[0]

        if conn is None:
            log.msg("Missing conn %s" % (conn))
            return False

        if chid is None or len(chid) == 0:
            chid = str(uuid.uuid4())

        self.chid = chid
        self.conn = conn
        return True

    def initialize(self):
        self.metrics = self.ap_settings.metrics

    def options(self, token):
        self._addCors()

    def head(self, token):
        self._addCors()

    def _addCors(self):
        if self.ap_settings.cors:
            self.set_header("Access-Control-Request-Method", "*")

    def _error(self, code, msg):
        self.set_status(code, msg)
        self.finish()
        return

    @cyclone.web.asynchronous
    def get(self, uaid=None):
        if uaid is None:
            return self._error(400, "invalid UAID")
        try:
            uuid.UUID(uaid)
        except Exception, e:
            log.msg("Improper UAID value specified %s" % e)
            return self._error(400, "invalid UAID")
        self.uaid = uaid

        self.chid = str(uuid.uuid4())
        self._registered(True)

    @cyclone.web.asynchronous
    def put(self, uaid=None):
        self.metrics = self.ap_settings.metrics
        self.start_time = time.time()

        self.add_header("Content-Type", "application/json")

        if uaid is None:
            uaid = str(uuid.uuid4())
        else:
            try:
                uuid.UUID(uaid)
            except ValueError:
                log.msg("Invalid UAID [%s], swapping for valid one" % uaid)
                uaid = str(uuid.uuid4())

        self.uaid = uaid
        if not self._load_params():
            log.msg("Invalid parameters")
            self.set_status(400, "Invalid arguments")
            self.finish()
            return
        d = deferToThread(self.pinger.register, self.uaid, self.conn)
        d.addCallback(self._registered)
        d.addErrback(self._error_response)

    def _registered(self, result):
        if not result:
            self.set_status(500, "Registration failure")
            return self.finish()
        d = deferToThread(MakeEndPoint,
                          self.ap_settings.fernet,
                          self.ap_settings.endpoint_url,
                          self.uaid,
                          self.chid)
        d.addCallbacks(self._return_channel,
                       self._error_response)

    def _return_channel(self, endpoint):
        msg = {"useragentid": self.uaid,
               "channelid": self.chid,
               "endpoint": endpoint}
        self.set_status(200)
        self.write(json.dumps(msg))
        return self.finish()
