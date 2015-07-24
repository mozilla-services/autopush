==================
Autopush Changelog
==================

1.3.0 (**dev**)
===============

Features
--------

* Add Sphinx docs with ReadTheDocs publishing. Issue #98.
  This change also includes a slight Metrics refactoring with a IMetrics
  interface, and renames MetricSink -> SinkMetrics for naming consistency.
* Add UDP Wake support. Issue #106
  Some devices which use SimplePush routing offer a feature to wake on
  a carrier provided UDP ping. See issue #106 for details.

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
* Add /status HTTP endpoint for autopush/autoendpoint. Resolves Issue #27.
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
