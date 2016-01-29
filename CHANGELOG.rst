==================
Autopush Changelog
==================

1.10.0 (2016-01-29)
===================

Features
--------

* Tag logged notifications based on whether they're for a webpush user or not.
  Issue #315.
* Add maintenance.py script for use in AWS Lambda. Issue #254.
* Add use_webpush base tag for websocket connections using web_push.
  Issue #205.
* Add log message if routing connection is refused. Issue #283.

Bug Fixes
---------

* Increase the type of connection loss exceptions caught by autopush that
  occur during deploys and node losses. Issue #306.

1.9.3 (2016-01-23)
==================

* Fix issue with users connecting with an invalid UAID that didn't exist in
  the database. Issue #304.

1.9.2 (2016-01-22)
==================

Bug Fixes
---------

* Reduce new UAID's to a single write, this time for real. Issue #300.

1.9.1 (2016-01-22)
==================

Bug Fixes
---------

* Reduce new UAID's to a single write on connect. Issue #300.
* Fixes for GCM JSON encoding rejections and ID assignment. Issue #297.


1.9.0 (2016-01-15)
==================

Features
--------

* Utilize router last_connect index to track whether a user has connected in
  the current month. Issue #253.
* Add message table rotation for webpush users. Issue #191.
* Capture Authorization header for endpoint requests for logging. Issue #232.
* New Bridge HTTP API. Issues #238, #250, #251.
  In cooperation with the GCM client work the HTTP Bridge API has been
  simplified. The new method has been detailed in /api/endpoint.py.
  In essence: The API is now bearer token based, and uses the form
  /v1/{BridgeType}/{BridgeToken}/registration[/{uaid}/[subscription/[{chid}]]]
* Tag endpoint requests with a unique ID. Issue #268.
* Fixed document reference to HTTP API to be a deep link.
* Pass either Encryption-Key or Crypto-Key per WebPush spec change. Issue #258.
* Removed refences to obsolete simplepush_test package.
* Convert outbound GCM data to base64. This should resolve potential
  transcription issues with binary encoded data going over the bridge.
  Issue #289.
* Record Requesting Hostname to metrics. Issue #228.
* Add key hash for UAIDs NOTE: enabling this will break all currently stored
  UAID records.

Bug Fixes
---------

* Fix bug in GCM router call not getting appropriate params dict. Issue #271.
* Ensure rotating message table exists on startup. Issue #266.
* Fix Running documents to reflect usage of local DynamoDB JAR server. Issue
  #265.
* Fixed scope issue around the Bridge API delete functions.
* Fix db test bug with month addition to properly handle December. Issue #261.
* Relax endpoint TLS cert requirement for https scheme. Issue #249.
* Add endpoint names to the docs. Issue #223.
* Moved Obsolete command arguments out of required path, and allow tester to ignore local configuration files. Issue #246

WebPush
-------

Configuration Changes
---------------------

* It is recommended that the following config options be moved to
  .autopush_shared.ini
  --gcm_enabled
  --senderid_list
  --senderid_expry

Backwards Incompatibilities
---------------------------

* The previous Bridge HTTP API has been removed.
* The Push message update mechanism has been removed. Issue #279.

Deprecated
----------

* The following configuration options have been deprecated and will soon
  be removed:
  --log_level
  --external_router (replaced by --apns_enabled)
  --max_message_size

1.8.1 (2015-11-16)
==================

Features
--------

* Convert proprietary AUTH to use Bearer Token for client REST interfaces.
  Issue #238.

Bug Fixes
---------

WebPush
-------

Configuration Changes
---------------------

* Please include the new `--auth_key` which is the base token set for
  generating bearer tokens. This uses the same format as the `--crypto_key`,
  but should be a different value to prevent possible key detection. The key
  can be generated using the same `bin/autokey` tool used to generate the
  crypto_key

1.8.0 (2015-11-13)
==================

Features
--------

* Server provided SenderID values for GCM router using clients
  The GCM router will randomly select one of a list of SenderIDs stored in
  S3 under the "oms-autopush"/"senderids" key. The values can
  be loaded into S3 either via the S3 console, or by running an instance of
  autopush and passing the values as the "senderid_list" argument. Issue #185.
* REST Registration will now return a valid ChannelID if one is not specified.
  Issue #182.
* Add hello timeout. Issue #169.
* Convert proprietary AUTH to use HAWK for client REST interfaces. Issue #201.
* Add DELETE /uaid[/chid] functions to client REST interfaces. Issue #183.
* Add .editorconfig for consistent styling in editors. Issue #218.
* Added --human_logs to display more human friendly logging.
* If you specify the --s3_bucket=None, the app will only use local memory
  and will not call out to the S3 repository. It is STRONGLY suggested that
  you specify the full --senderid_list data set.
* You may now specify multiple keys for the crypto_key value. Values should
  be a list ordered from newest to oldest allowed key.

Bug Fixes
---------

* Capture all ProvisionedException errors in websocket and endpoint correctly.
  Issue #175.
* Clean-up several recent deferToLater calls that didn't have their cancelled
  exceptions ignored. Issue #208.
* Fix improper attribute reference in delete call. Issue #211.
* Always include TTL header in response to a WebPush notification. Issue #194.
* Increased unit test coverage due to removal of proprietary AUTH.
* Fixed issue with local senderid data cache. (discovered while debugging.)

WebPush
-------

Backwards Incompatibilities
---------------------------
* Do not specify values for boolean flags.
* 'cors' is now enabled by default. In it's place use --nocors if you wish
  to disable CORS. Please remove "cors" flag from configuration files.
* Do not specify --gcm_apikey. Instead, store the API key and senderid as
  values in S3. The data may still be written as a JSON string such as:
  ' "`_senderID_`": {"auth": "`_api_key`"}}'
  activate the GCM bridge by specifying --gcm_enabled.

1.7.2 (2015-10-24)
==================

Bug Fixes
---------

* Set SSL mode properly for release buffers.

1.7.1 (2015-10-23)
==================

Bug Fixes
---------

* Change HOSTNAME env name to not conflict with AWS env. Issue #198
* Move endpoint_* marks to shared variables.

1.7.0 (2015-10-21)
==================

Features
--------

* Add UDP Wake support. Some devices which use SimplePush routing offer a
  feature to wake on a carrier provided UDP ping. Issue #106.
* Provide service environment information to help clients identify the service
  environment, server provides it along with the hello message. Issue #50.
* Add actionable JSON errors to the Endpoint responses. Issue #178.

Bug Fixes
---------

* Reset UAIDs for clients that change their router type. PR #167.
* Respond with status code 413 for payloads that exceed the maximum size,
  404 for invalid tokens, and 400 for missing encryption headers. PR #170.

WebPush
-------

* Add Push message update mechanism. Issue #141.

1.6.0 (2015-09-14)
==================

Bug Fixes
---------

* log_exception no longer re-raises the exception, which was causing onClose
  to not return thus letting the connectionCount not be decremented.
* Check for stale connection nodes when routing. Issue #163.
* Remove logging of sendClose, as its unactionable noise. Add metric for
  sendClose success. Remove final verifyNuke as its never run in the several
  months it was in, indicating that abortConnection is 100% effective.
  Issue #161.
* Rename `SimplePushServerProtocol` to `PushServerProtocol`. Issue #117.

WebPush
-------

* Add an endpoint for deleting undelivered messages. PR #131.

1.5.1 (2015-09-02)
==================

Bug Fixes
---------

* Don't require nose to be installed to run.

1.5.0 (2015-09-02)
==================

Bug Fixes
---------

* Don't cancel a deferred that was already called.
* Restore logging of simplepush successfull/stored delivery based on status.
* Restore updates.handled endpoint timer to track time to deliver.

Features
--------

* Memory profile benchmarking on a connection, displays in test results. Issue
  #142.
* Refactor of attribute assignment to the Websocket instance to avoid memory
  increases due to Python reallocating the underlying dict datastructure. Issue
  #149.
* Add close_handshake_timeout option, with default of 0 to let our own close
  timer handle clean-up.
* Up default close handshake timer to 10 seconds for slower clients.
* Add channel id logging to endpoint.

1.4.1 (2015-08-31)
==================

Bug Fixes
---------

* Expose Web Push headers for CORS requests. PR #148.
* Expose argument for larger websocket message sizes (to fix issue #151)
  Clients with a large number of channelIDs (50+) can cause the initial
  connection to fail. A proper solution is to modify the client to not send
  ChannelIDs as part of the "hello" message, but being able to increase the
  message size on the server should keep the server from dying up front.
  This fix should only impact clients with large numbers of registered channels,
  notably, devs.

1.4.0 (2015-08-27)
==================

Bug Fixes
---------

* Fix _notify_node to not attempt delivering to ourselves at the end of the
  client connection.
* Remove adaptive ping entirely. Send special close code and drop clients that
  ping more frequently than 55 seconds (approx 1 min). This will result in
  clients that ping too much being turned away for awhile, but will alleviate
  data/battery issues in buggy mobile clients. Issue #103.
* Store and transmit encrypted Web Push messages as Base64-encoded strings.
  PR #135.

Features
--------

* Add /status HTTP endpoint for autopush. Issue #136.
* Log all disconnects, whether they were clean, the code, and the reason.
* Allow encryption headers to be omitted for blank messages. Issue #132.

1.3.3 (2015-08-18)
==================

* Handle None values in ack updates.

1.3.2 (2015-08-11)
==================

Bug Fixes
---------

* Fix deferToLater to not call the function if it was cancelled using a
  canceller function.
* Fix finish_webpush_notifications to not immediately call
  process_notifications as that will be called as needed after ack's have been
  completed.
* Fix process_ack to not call process_notifications when using webpush if there
  are still remaining notifications to ack.

Features
--------

* Integrate simplepush_test smoke-test client with the main autopush test-suite
  into the test-runner. Issue #119.

1.3.1 (2015-08-04)
==================

Bug Fixes
---------

* Fix RouterException to allow for non-logged responses. Change
  RouterException's to only log actual exceptions that should be address in
  bug-fixes. Issue #125.

1.3.0 (2015-07-29)
==================

Features
--------

* Add WebPush TTL scheme per spec (as of July 28th 2015). Issue #56.
* Add WebPush style data delivery with crypto headers to connected clients.
  Each message is stored independently in a new message table, with the version
  and channel id still required to ack a message. The version is a UUID4 hex
  which is also echo'd back to the AppServer as a Location URL per the current
  WebPush spec (as of July 28th 2015). Issue #57.
* Add Sphinx docs with ReadTheDocs publishing. Issue #98.
  This change also includes a slight Metrics refactoring with a IMetrics
  interface, and renames MetricSink -> SinkMetrics for naming consistency.

Bug Fixes
---------

* Increase test coverage of utils for 100% test coverage.
* Move all dependencies into requirements.txt and freeze them all explicitly.

Internal
--------

* Refactor proprietary ping handling for modularized dispatch. Issue #82.

  Major changes

  - RegistrationHandler endpoint is now the sole method for registering for a
    proprietary wake / transport.
  - ``connect`` data from websocket hello is ignored.
  - Unit Testing has been increased to ~ 100% test coverage.
  - Proprietary Ping and Bridge terminology has been replaced with the terms
    router_type / router_data. Router type being one of simplepush / apns / gcm
    and eventually webpush. Router data is an arbitrary JSON value as
    appropriate for the router type.

  db.py

  - Removed previous methods (deleteByToken/get_connection/etc) as all the
    router data is included as a single JSON blob for DynamoDB to store.
  - Change register_user to use UpdateItem to avoid overwriting router data
    when connecting via websocket.

  endpoint.py

  - EndpointHandler and RegistrationHandler now both inherit from a common
    baseclass: AutoendpointHandler. This baseclass implements
    OPTIONS/HEAD methods, sets the appropriate CORS headers, and has several
    shared error handlers.
  - A notification has been standardized into a Notification namedtuple.
  - RegistrationHandler API has been changed to have PUT and POST methods.
  - EndpointHandler has been refactored to use the new Router interface.
  - EndpointHandler now uses a basic HMAC auth scheme, GET/PUT with existing
    UAID's require an appropriate HMAC attached with the original derived
    shared key. (Documented in the RegistrationHandler.get method)

  websocket.py

  - Removed use of ``connect`` data in hello message as RegistrationHandler is
    now the sole method of registering other routers.

  router/interface.py (NEW)

  - IRouter object that all notification routers must implement. This handles
    verifying router data during registration, and is responsible for actual
    delivery of notifications.
  - RouterException / RouterResponse objects for returning appropriate data
    during register/route_notification calls.

  router/apnsrouter.py

  - Moved from bridge/apns.
  - Refactored to use RouterException/RouterResponse.

  router/gcm.py

  - Moved from bridge/gcm.
  - Refactored to use RouterException/RouterResponse.
  - Removed internal message retries, now returns a 503 in that case for the
    Application Server to retry delivery.

  router/simple.py

  - Moved code out from endpoint.py.
  - Refactored existing simplepush routing scheme to use twisted inline
    deferreds to track the logic with less headaches.


Backward Incompatibilities
--------------------------

* ``bridge`` option is now ``external_router``.

1.2.3 (2015-06-02)
==================

Features
--------

* Additional logging/metrics on auto-ping and connection aborting.

1.2.2 (2015-05-27)
==================

Features
--------

* Add additional metrics for writers/readers to indicate what twisted is still
  tracking connection-wise.

Bug Fixes
---------
* Correct trap for TCP connection closer

1.2.1 (2015-05-20)
==================

Bug Fixes
---------
* Fix error with blank UAIDs being rejected as "already registered"

1.2.0 (2015-05-19)
==================

Features
--------

* Pong delay can no longer be set, and uses an adaptive value based on the last
  ping to try and accurately compensate for higher latency connections. This
  also removes the min_ping_interval option such that if a client is pinging
  too frequently we will instead leave space for up to the clients timeout of
  10-sec (a hardcoded client value).

Bug Fixes
---------

* Fix 500 errors in endpoint caused by timeouts when trying to deliver to
  expired nodes in the cluster. Resolves Issue #75.
* Add CancelledError trap to all deferreds in websocket.py. Resolves Issue #74.
* Aggressively delete old TCP connections on device reregistration (#72)

Backwards Incompatibility
-------------------------

* Removed min_ping_interval config option.
* Removed pong_delay config option.

1.1rc2 (2015-05-15)
===================

Features
--------

* Add structured logging output for the endpoint for additional request
  metadata. Resolves Issue #67.

Bug Fixes
---------

* Fix bug with deferreds not being tracked, causing access to objects that were
  cleaned up. Resolves Issue #66.
* kill older, duplicate UAID entries that may still be connected.
* use Websocket Pings to detect dead connections.

1.0rc1 (2015-04-29)
===================

Features
--------

* Verify ability to read/write DynamoDB tables on startup. Resolves Issue #46.
* Send un-acknolwedged direct delivery messages to the router if the client is
  disconnected without ack'ing them. Resolves Issue #36.
* Use IProducer to more precisely monitor when the client has drained the data
  to immediately resume sending more data. Resolves Issue #28.
* Add /status HTTP endpoint for autoendpoint. Resolves Issue #27.
* Add example stage/prod config files. Resolves Issue #22.
* Switch internal routing from requests to twisted http-client. Resolves Issue
  #21.
* Add logging for user-agent to metrics tags. Resolves Issue #20.
* Add Datadog stats output. Resolves Issue #17.
* Add GCM and APNS Bridges. Resolves Issue #16.
* Use eliot structured logging for stdout logging that matches ops standard
  for logging. Resolves Issue #11.
* Allow storage/router table names to be configurable. Resolves Issue #4.
* Added optional CORS headers (use --cors to enable). Resolves Issue #3.
* Add provisioned error metrics to track when throughput is exceeded in AWS
  DynamoDB. Resolves Issue #2.
* Add Sentry support (SENTRY_DSN must be set in the environment). Resolves
  Issue #1.

Bug Fixes
---------

* Capture and log exceptions in websocket protocol functions.
* Fix bug with 'settings' in cyclone overriding cyclone's settings. Resolves
  Issue #13.
