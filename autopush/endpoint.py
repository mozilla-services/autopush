import hashlib
import json
import time
import urlparse
import uuid

import cyclone.web
from boto.dynamodb2.exceptions import (
    ProvisionedThroughputExceededException,
)
from cryptography.fernet import InvalidToken
from repoze.lru import LRUCache
from StringIO import StringIO
from twisted.internet.threads import deferToThread
from twisted.internet.error import ConnectionRefusedError, UserError
from twisted.python import failure, log
from twisted.web.client import FileBodyProducer

from autopush.protocol import IgnoreBody


dead_cache = LRUCache(150)


class EndpointHandler(cyclone.web.RequestHandler):
    def initialize(self):
        self.uaid_hash = None
        self.metrics = self.ap_settings.metrics

    def _node_key(self, node_id):
        return node_id + "-%s" % int(time.time()/3600)

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

    def _client_info(self):
        """Returns a dict of additional client data"""
        return {
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "uaid_hash": getattr(self, "uaid_hash", ""),
        }

    @cyclone.web.asynchronous
    def put(self, token):
        self.start_time = time.time()
        fernet = self.ap_settings.fernet

        self._load_params()
        self._addCors()
        if self.data and len(self.data) > self.ap_settings.max_data:
            self.set_status(401)
            log.msg("Data too large", **self._client_info())
            self.write("Data too large")
            return self.finish()

        d = deferToThread(fernet.decrypt, token.encode('utf8'))
        d.addCallback(self._process_token)
        d.addErrback(self._bad_token).addErrback(self._error_response)

    def _addCors(self):
        if self.ap_settings.cors:
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods", "PUT")

    def _process_token(self, result):
        self.uaid, self.chid = result.split(":")

        d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
        d.addCallback(self._process_uaid)
        d.addErrback(self._handle_overload).addErrback(self._error_response)

    def _bad_token(self, failure):
        failure.trap(InvalidToken)
        self.set_status(401)
        log.msg("Invalid token", **self._client_info())
        self.write("Invalid token")
        self.finish()

    def _handle_overload(self, failure):
        failure.trap(ProvisionedThroughputExceededException)
        self.set_status(503)
        log.msg("Throughput Exceeded", **self._client_info())
        self.write("Server busy, try later")
        self.finish()

    def _error_response(self, failure):
        log.err(failure, **self._client_info())
        self.set_status(500)
        self.write("Error processing request")
        self.finish()

    def _process_uaid(self, result):
        """Process the result of the AWS call"""
        if not result:
            self.set_status(404)
            log.msg("UAID not found in AWS.", **self._client_info())
            self.write("Invalid")
            return self.finish()
        uaid = result.get('uaid')
        if uaid:
            self.uaid_hash = hashlib.sha224(uaid).hexdigest()

        d = deferToThread(self.ap_settings.storage.get_connection,
                          uaid)
        d.addCallback(self._send_pping, uaid, result)
        d.addErrback(self._error_response)

    def _send_pping(self, pping_info, uaid, routeinfo):
        try:
            if pping_info is not None:
                d = deferToThread(
                    self.bridge.ping,
                    self.uaid,
                    self.version,
                    self.data,
                    pping_info)
                d.addCallback(self._process_pping, routeinfo)
                d.addErrback(self._error_response)
                return
        except AttributeError:
            pass
        self._process_route(routeinfo)

    def _process_pping(self, result, routeinfo):
        if not result:
            log.msg("proprietary ping failed, falling back to routing",
                    **self._client_info())
            return self._process_route(routeinfo)
        # Ping handoff succeeded, no further action required
        self.metrics.increment("router.pping.hit")
        # Since we're handing off, return 202
        self.set_status(202)
        log.msg("proprietary ping success", **self._client_info())
        self.write("Success")
        self.finish()

    def _process_route(self, result):
        # Determine if they're connected at the moment
        node_id = result.get("node_id")

        # Indicator if we got a node_id, but the node won't handle
        # delivery at this moment later.
        self.client_check = False

        if node_id and dead_cache.get(self._node_key(node_id)):
            return self._process_routing(None, result)
        elif node_id:
            # Attempt a delivery if they are connected
            d = self._send_notification(node_id)
            d.addCallback(self._process_routing, result)
            d.addErrback(self._process_agent_fail, result)
            d.addErrback(self._error_response)
        else:
            self._save_notification()

    def _send_notification(self, node_id):
        payload = json.dumps([{"channelID": self.chid,
                               "version": self.version,
                               "data": self.data}])
        url = node_id + "/push/" + self.uaid
        return self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
            bodyProducer=FileBodyProducer(StringIO(payload)),
        ).addCallback(IgnoreBody.ignore)

    def _send_notification_check(self, node_id):
        url = node_id + "/notif/" + self.uaid
        return self.ap_settings.agent.request(
            "PUT",
            url.encode("utf8"),
        ).addCallback(IgnoreBody.ignore)

    def _process_agent_fail(self, fail, item):
        fail.trap(ConnectionRefusedError, UserError)
        dead_cache.put(self._node_key(item["node_id"]), True)
        log.err("Agent failed to connect to host: %s" % item["node_id"],
                **self._client_info())
        self.metrics.increment("updates.client.host_gone")
        self._process_routing(False, item)

    def _process_routing(self, response, item):
        node_id = item.get("node_id")
        if response and response.code == 200:
            # Success, return!
            self.metrics.increment("router.broadcast.hit")
            time_diff = time.time() - self.start_time
            self.metrics.timing("updates.handled", duration=time_diff)
            self.write("Success")
            log.msg("Successful delivery", **self._client_info())
            return self.finish()
        elif not response or response.code == 404:
            # Conditionally delete the node_id
            d = deferToThread(self.ap_settings.router.clear_node, item)
            d.addCallback(self._process_node_delete)
            d.addErrback(self._handle_overload)
            d.addErrback(self._error_response)
            return

        # Client was busy, remember to tell it to check
        self.client_check = response.code == 503
        self._save_notification(node_id)

    def _process_node_delete(self, result):
        if not result:
            # Client hopped, punt this request so app-server can
            # try again and get luckier
            self.set_status(503)
            self.write("Server is busy")
            self.metrics.increment("updates.client.hop")
            log.msg("Client hopped between delivery", **self._client_info())
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
            d = self._send_notification_check(node_id)
            d.addCallback(self._process_notif, node_id)
            d.addErrback(self._notif_check_fail, node_id)
            d.addErrback(self._error_response)
        else:
            # Saved the notification, check for if the client is somewhere
            # now
            d = deferToThread(self.ap_settings.router.get_uaid, self.uaid)
            d.addCallback(self._process_jumped_client)
            d.addErrback(self._handle_overload)
            d.addErrback(self._error_response)

    def _notif_check_fail(self, fail, node_id):
        """Handle the inability to contact a node to inform it of the
        notification

        In this case, we were unable to notify the node, but we've saved the
        notification, so skip to acknowledging.

        """
        fail.trap(ConnectionRefusedError, UserError)
        dead_cache.put(self._node_key(node_id), True)
        self._finish_missed_store()

    def _process_notif(self, response, node_id=None):
        """Process the result of a PUT to a Connection Node's /notif/
        handler"""
        if response.code != 404:
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
            self.metrics.increment("updates.client.deleted")
            log.msg("Client deleted during delivery", **self._client_info())
            return self.finish()

        node_id = result.get("node_id")
        if not node_id:
            return self._finish_missed_store()

        # Is this a dead node?
        if dead_cache.get(self._node_key(node_id)):
            return self._finish_missed_store()

        d = self._send_notification_check(node_id)
        # No check on response here, because if they jumped since we
        # got this they'll definitely get the stored notification
        # We ignore errors here too, as that's a hell of an edge case
        d.addBoth(self._finish_missed_store)

    def _finish_missed_store(self, result=None):
        self.metrics.increment("router.broadcast.miss")
        # since we're handing off, return 202
        log.msg("Router miss, message stored.", **self._client_info())
        self.set_status(202)
        self.write("Success")
        self.finish()

    def write_error(self, code, **kwargs):
        """ Write the error (otherwise unhandled exception when dealing with
        unknown method specifications.) """
        self.set_status(code)
        if "exc_info" in kwargs:
            log.err(failure.Failure(*kwargs["exc_info"]),
                    **self._client_info())
        else:
            log.err("Error in handler: %s" % code, **self._client_info())
        self.finish()


class RegistrationHandler(cyclone.web.RequestHandler):
    def _client_info(self):
        """Returns a dict of additional client data"""
        return {
            "user-agent": self.request.headers.get("user-agent", ""),
            "remote-ip": self.request.headers.get("x-forwarded-for",
                                                  self.request.remote_ip),
            "uaid_hash": getattr(self, "uaid_hash", ""),
        }

    def _error_response(self, failure):
        log.err(failure, **self._client_info())
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
            log.msg("Missing %s %s" % (tags['conn'], conn))
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
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Methods", "GET,PUT")

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
                log.msg("Invalid UAID [%s], swapping for valid one" % uaid,
                        **self._client_info())
                uaid = str(uuid.uuid4())

        self.uaid = uaid
        if not self._load_params():
            log.msg("Invalid parameters", **self._client_info())
            self.set_status(400, "Invalid arguments")
            self.finish()
            return
        d = deferToThread(self.bridge.register, self.uaid, self.conn)
        d.addCallback(self._registered)
        d.addErrback(self._error_response)

    def _registered(self, result):
        if not result:
            self.set_status(500, "Registration failure")
            log.err("Registration failure", **self._client_info())
            return self.finish()
        d = deferToThread(self.ap_settings.makeEndpoint,
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
        log.msg("Endpoint registered via HTTP", **self._client_info())
        return self.finish()
