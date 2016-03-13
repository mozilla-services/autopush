<a name="1.13.2"></a>
## 1.13.2 (2016-03-13)


#### Features

*   validate v0 tokens more thoroughly ([77373cd6](https://github.com/mozilla-services/autopush/commit/77373cd65d91603e39b80ed52d6312a86779ac75), closes [#406](https://github.com/mozilla-services/autopush/issues/406))

#### Bug Fixes

*   Clear corrupted router records ([5580e0d2](https://github.com/mozilla-services/autopush/commit/5580e0d2e3a99035c899721bf36e6f1018f38e38), closes [#400](https://github.com/mozilla-services/autopush/issues/400))
*   clear only the node_id in the router record ([a1ee817c](https://github.com/mozilla-services/autopush/commit/a1ee817c4cabfc5f5352961bdec5262ece3131a0), closes [#401](https://github.com/mozilla-services/autopush/issues/401))


<a name="1.13.1"></a>
## 1.13.1 (2016-03-10)


#### Test

*   fix timing issue in last connect test ([c4039df1](https://github.com/mozilla-services/autopush/commit/c4039df1e159d17f64a316dc8378a64c458ad7fe))

#### Chore

*   fix changelog and clog for past commit oopsies ([90c3ab16](https://github.com/mozilla-services/autopush/commit/90c3ab16addc150d17a161cf091b8a2ea9239d68))
*   update version for 1.13.1 ([7a960b4c](https://github.com/mozilla-services/autopush/commit/7a960b4ce24e7c9225a053f63a038f3a5c6d28c5))

#### Bug Fixes

*   default api_ver to v0 for message endpoint ([86ba66d4](https://github.com/mozilla-services/autopush/commit/86ba66d46792c8cbd746c706c82390e6823ef686), closes [#395](https://github.com/mozilla-services/autopush/issues/395))


<a name="1.13"></a>
## 1.13 (2016-03-07)


#### Features

*   allow channels to register with public key ([3d15b9bb](https://github.com/mozilla-services/autopush/commit/3d15b9bbc5002d8c6b03b3fd57418aa1892be0e7), closes [#326](https://github.com/mozilla-services/autopush/issues/326))
*   accept nack messages, log code for ack/unreg/nack ([2030a4df](https://github.com/mozilla-services/autopush/commit/2030a4df980a9fc04c7edaae85fb57175510481e), closes [#380](https://github.com/mozilla-services/autopush/issues/380))

#### Bug Fixes

*   send raven calls to event loop ([d35a78d4](https://github.com/mozilla-services/autopush/commit/d35a78d44c0838d2b72492b23031614611e960dd), closes [#387](https://github.com/mozilla-services/autopush/issues/387))
*   capture ValueError for empty notifications arrays ([ce27f1e3](https://github.com/mozilla-services/autopush/commit/ce27f1e383886219710786f9d5233e6e7bc95226), closes [#385](https://github.com/mozilla-services/autopush/issues/385))
*   don't return 503 for disconnected user ([43a2e906](https://github.com/mozilla-services/autopush/commit/43a2e90692e81742afe9a44bf836079bcaf2604d), closes [#378](https://github.com/mozilla-services/autopush/issues/378))
*   force header values to lowercase underscored values ([b4517aeb](https://github.com/mozilla-services/autopush/commit/b4517aeb4c804d0d03063d31dd00ea9db4b39bc1), closes [#373](https://github.com/mozilla-services/autopush/issues/373))
*   change message_type to message_source ([d603902c](https://github.com/mozilla-services/autopush/commit/d603902ce7a01ad140eb69c61dd7935a8370315b))
*   pass TTL Header value to GCM ([c5ae841c](https://github.com/mozilla-services/autopush/commit/c5ae841cbd7f8e31dc72f6f42ae1ffe53d5d4078))

<a name="1.12.1"></a>
### 1.12.1 (2016-02-25)


#### Bug Fixes

*   Normalize encryption headers. ([b9c3cc57](https://github.com/mozilla-services/autopush/commit/b9c3cc571fbdce3c2d748a8ad4efd2431c005bdc))
*   allow stored ttl of None to be treated as 0 ([2b75be5f](https://github.com/mozilla-services/autopush/commit/2b75be5fb79d8bd6dc410cea44b6153ec9446b3a), closes [#366](https://github.com/mozilla-services/autopush/issues/366))
*   silence missing TTL errors from sentry log ([c167ee2f](https://github.com/mozilla-services/autopush/commit/c167ee2fdcceb79a21c47eff0ddc46fe4e0b9e9e))

<a name="1.12.0"></a>
## 1.12.0 (2016-02-23)


#### Doc

*   add text and links for 400:111 errors ([515be293](https://github.com/mozilla-services/autopush/commit/515be2939c12dc5b5720e3fcdb2fd7a0e0d60e6b))
*   update CONTRIBUTING.md doc to match our style ([214e8a77](https://github.com/mozilla-services/autopush/commit/214e8a77c890803846bfc6133dafd2b9e1ae2662))

#### Features

*   upgrade autobahn/twisted to 0.12/15.5 ([47597a0d](https://github.com/mozilla-services/autopush/commit/47597a0da8a401aac38167632d316c48c34c3299), closes [#180](https://github.com/mozilla-services/autopush/issues/180))
*   add user-agent logging to acks ([1dbe3460](https://github.com/mozilla-services/autopush/commit/1dbe3460028ae7980fe5a1722f2499e3428838f3))

#### Bug Fixes

*   allow webpush w/no ttl & cleanup 400 logging ([1f01cd70](https://github.com/mozilla-services/autopush/commit/1f01cd70f52de3c22f74a7389019dfafd1d90ea7), closes [#358](https://github.com/mozilla-services/autopush/issues/358))

#### Chore

*   bring project up to standard guidelines ([c2baf49f](https://github.com/mozilla-services/autopush/commit/c2baf49fd6310dde221151a2d088c6c9f6ca7c9f), closes [#344](https://github.com/mozilla-services/autopush/issues/344))

1.11.0 (2016-02-16)
-------------------

### Features

-   Log notifications out of autopush nodes for data on when they were
    actually delivered to clients. Issue \#331.
-   Added VAPID auth support to incoming Push POSTs. Issue \#325. This
    does not yet use token caches since that will introduce database
    changes as well as impact a fair bit more code.
-   Require TTL header for all incoming subscription updates. Issue
    \#329.
-   Added "Location" header to all successful outbound webpush
    subscription update responses. Issue \#338.
-   Whitelist the "Authorization" header for CORS requests. PR \#341.
-   Add a "WWW-Authenticate" header for 401 responses. PR \#341.

### Bug Fixes

-   Use appropriate 400, 404, 410 status codes for differing message
    endpoint results, rather than always a 404. Issue \#312.
-   Do not send useless 'ver' across GCM bridge. Issue \#323.

### Backwards Incompatibilities

-   The TTL header is now required for all subscription updates.
    Messages without this header will return a 400 error (errno 111).

1.10.1 (2016-02-01)
-------------------

### Bug Fixes

-   Use non-conditional update for save\_messages as put\_item relies on
    a flakey conditional check that doesn't apply in our case. Issue
    \#320.
-   Run looping task call to update message table objects on the
    endpoint as well as the connection node. Issue \#319.

1.10.0 (2016-01-29)
-------------------

### Features

-   Tag logged notifications based on whether they're for a webpush user
    or not. Issue \#315.
-   Add maintenance.py script for use in AWS Lambda. Issue \#254.
-   Add use\_webpush base tag for websocket connections using web\_push.
    Issue \#205.
-   Add log message if routing connection is refused. Issue \#283.

### Bug Fixes

-   Increase the type of connection loss exceptions caught by autopush
    that occur during deploys and node losses. Issue \#306.

1.9.3 (2016-01-23)
------------------

-   Fix issue with users connecting with an invalid UAID that didn't
    exist in the database. Issue \#304.

1.9.2 (2016-01-22)
------------------

### Bug Fixes

-   Reduce new UAID's to a single write, this time for real. Issue
    \#300.

1.9.1 (2016-01-22)
------------------

### Bug Fixes

-   Reduce new UAID's to a single write on connect. Issue \#300.
-   Fixes for GCM JSON encoding rejections and ID assignment. Issue
    \#297.

1.9.0 (2016-01-15)
------------------

### Features

-   Utilize router last\_connect index to track whether a user has
    connected in the current month. Issue \#253.
-   Add message table rotation for webpush users. Issue \#191.
-   Capture Authorization header for endpoint requests for logging.
    Issue \#232.
-   New Bridge HTTP API. Issues \#238, \#250, \#251. In cooperation with
    the GCM client work the HTTP Bridge API has been simplified. The new
    method has been detailed in /api/endpoint.py. In essence: The API is
    now bearer token based, and uses the form
    /v1/{BridgeType}/{BridgeToken}/registration[/{uaid}/[subscription/[{chid}]]]
-   Tag endpoint requests with a unique ID. Issue \#268.
-   Fixed document reference to HTTP API to be a deep link.
-   Pass either Encryption-Key or Crypto-Key per WebPush spec change.
    Issue \#258.
-   Removed refences to obsolete simplepush\_test package.
-   Convert outbound GCM data to base64. This should resolve potential
    transcription issues with binary encoded data going over the bridge.
    Issue \#289.
-   Record Requesting Hostname to metrics. Issue \#228.
-   Add key hash for UAIDs NOTE: enabling this will break all currently
    stored UAID records.

### Bug Fixes

-   Fix bug in GCM router call not getting appropriate params dict.
    Issue \#271.
-   Ensure rotating message table exists on startup. Issue \#266.
-   Fix Running documents to reflect usage of local DynamoDB JAR server.
    Issue \#265.
-   Fixed scope issue around the Bridge API delete functions.
-   Fix db test bug with month addition to properly handle December.
    Issue \#261.
-   Relax endpoint TLS cert requirement for https scheme. Issue \#249.
-   Add endpoint names to the docs. Issue \#223.
-   Moved Obsolete command arguments out of required path, and allow
    tester to ignore local configuration files. Issue \#246

### WebPush

### Configuration Changes

-   It is recommended that the following config options be moved to
    .autopush\_shared.ini --gcm\_enabled --senderid\_list
    --senderid\_expry

### Backwards Incompatibilities

-   The previous Bridge HTTP API has been removed.
-   The Push message update mechanism has been removed. Issue \#279.

### Deprecated

-   The following configuration options have been deprecated and will
    soon be removed: --log\_level --external\_router (replaced by
    --apns\_enabled) --max\_message\_size

1.8.1 (2015-11-16)
------------------

### Features

-   Convert proprietary AUTH to use Bearer Token for client REST
    interfaces. Issue \#238.

### Bug Fixes

### WebPush

### Configuration Changes

-   Please include the new --auth\_key which is the base token set for
    generating bearer tokens. This uses the same format as the
    --crypto\_key, but should be a different value to prevent possible
    key detection. The key can be generated using the same bin/autokey
    tool used to generate the crypto\_key

1.8.0 (2015-11-13)
------------------

### Features

-   Server provided SenderID values for GCM router using clients The GCM
    router will randomly select one of a list of SenderIDs stored in S3
    under the "oms-autopush"/"senderids" key. The values can be loaded
    into S3 either via the S3 console, or by running an instance of
    autopush and passing the values as the "senderid\_list" argument.
    Issue \#185.
-   REST Registration will now return a valid ChannelID if one is not
    specified. Issue \#182.
-   Add hello timeout. Issue \#169.
-   Convert proprietary AUTH to use HAWK for client REST interfaces.
    Issue \#201.
-   Add DELETE /uaid[/chid] functions to client REST interfaces. Issue
    \#183.
-   Add .editorconfig for consistent styling in editors. Issue \#218.
-   Added --human\_logs to display more human friendly logging.
-   If you specify the --s3\_bucket=None, the app will only use local
    memory and will not call out to the S3 repository. It is STRONGLY
    suggested that you specify the full --senderid\_list data set.
-   You may now specify multiple keys for the crypto\_key value. Values
    should be a list ordered from newest to oldest allowed key.

### Bug Fixes

-   Capture all ProvisionedException errors in websocket and endpoint
    correctly. Issue \#175.
-   Clean-up several recent deferToLater calls that didn't have their
    cancelled exceptions ignored. Issue \#208.
-   Fix improper attribute reference in delete call. Issue \#211.
-   Always include TTL header in response to a WebPush notification.
    Issue \#194.
-   Increased unit test coverage due to removal of proprietary AUTH.
-   Fixed issue with local senderid data cache. (discovered while
    debugging.)

### WebPush

### Backwards Incompatibilities

-   Do not specify values for boolean flags.
-   'cors' is now enabled by default. In it's place use --nocors if you
    wish to disable CORS. Please remove "cors" flag from configuration
    files.
-   Do not specify --gcm\_apikey. Instead, store the API key and
    senderid as values in S3. The data may still be written as a JSON
    string such as: ' "\_senderID\_": {"auth": "\_api\_key"}}' activate
    the GCM bridge by specifying --gcm\_enabled.

1.7.2 (2015-10-24)
------------------

### Bug Fixes

-   Set SSL mode properly for release buffers.

1.7.1 (2015-10-23)
------------------

### Bug Fixes

-   Change HOSTNAME env name to not conflict with AWS env. Issue \#198
-   Move endpoint\_\* marks to shared variables.

1.7.0 (2015-10-21)
------------------

### Features

-   Add UDP Wake support. Some devices which use SimplePush routing
    offer a feature to wake on a carrier provided UDP ping. Issue \#106.
-   Provide service environment information to help clients identify the
    service environment, server provides it along with the hello
    message. Issue \#50.
-   Add actionable JSON errors to the Endpoint responses. Issue \#178.

### Bug Fixes

-   Reset UAIDs for clients that change their router type. PR \#167.
-   Respond with status code 413 for payloads that exceed the maximum
    size, 404 for invalid tokens, and 400 for missing encryption
    headers. PR \#170.

### WebPush

-   Add Push message update mechanism. Issue \#141.

1.6.0 (2015-09-14)
------------------

### Bug Fixes

-   log\_exception no longer re-raises the exception, which was causing
    onClose to not return thus letting the connectionCount not be
    decremented.
-   Check for stale connection nodes when routing. Issue \#163.
-   Remove logging of sendClose, as its unactionable noise. Add metric
    for sendClose success. Remove final verifyNuke as its never run in
    the several months it was in, indicating that abortConnection is
    100% effective. Issue \#161.
-   Rename SimplePushServerProtocol to PushServerProtocol. Issue \#117.

### WebPush

-   Add an endpoint for deleting undelivered messages. PR \#131.

1.5.1 (2015-09-02)
------------------

### Bug Fixes

-   Don't require nose to be installed to run.

1.5.0 (2015-09-02)
------------------

### Bug Fixes

-   Don't cancel a deferred that was already called.
-   Restore logging of simplepush successfull/stored delivery based on
    status.
-   Restore updates.handled endpoint timer to track time to deliver.

### Features

-   Memory profile benchmarking on a connection, displays in test
    results. Issue \#142.
-   Refactor of attribute assignment to the Websocket instance to avoid
    memory increases due to Python reallocating the underlying dict
    datastructure. Issue \#149.
-   Add close\_handshake\_timeout option, with default of 0 to let our
    own close timer handle clean-up.
-   Up default close handshake timer to 10 seconds for slower clients.
-   Add channel id logging to endpoint.

1.4.1 (2015-08-31)
------------------

### Bug Fixes

-   Expose Web Push headers for CORS requests. PR \#148.
-   Expose argument for larger websocket message sizes (to fix issue
    \#151) Clients with a large number of channelIDs (50+) can cause the
    initial connection to fail. A proper solution is to modify the
    client to not send ChannelIDs as part of the "hello" message, but
    being able to increase the message size on the server should keep
    the server from dying up front. This fix should only impact clients
    with large numbers of registered channels, notably, devs.

1.4.0 (2015-08-27)
------------------

### Bug Fixes

-   Fix \_notify\_node to not attempt delivering to ourselves at the end
    of the client connection.
-   Remove adaptive ping entirely. Send special close code and drop
    clients that ping more frequently than 55 seconds (approx 1 min).
    This will result in clients that ping too much being turned away for
    awhile, but will alleviate data/battery issues in buggy mobile
    clients. Issue \#103.
-   Store and transmit encrypted Web Push messages as Base64-encoded
    strings. PR \#135.

### Features

-   Add /status HTTP endpoint for autopush. Issue \#136.
-   Log all disconnects, whether they were clean, the code, and the
    reason.
-   Allow encryption headers to be omitted for blank messages. Issue
    \#132.

1.3.3 (2015-08-18)
------------------

-   Handle None values in ack updates.

1.3.2 (2015-08-11)
------------------

### Bug Fixes

-   Fix deferToLater to not call the function if it was cancelled using
    a canceller function.
-   Fix finish\_webpush\_notifications to not immediately call
    process\_notifications as that will be called as needed after ack's
    have been completed.
-   Fix process\_ack to not call process\_notifications when using
    webpush if there are still remaining notifications to ack.

### Features

-   Integrate simplepush\_test smoke-test client with the main autopush
    test-suite into the test-runner. Issue \#119.

1.3.1 (2015-08-04)
------------------

### Bug Fixes

-   Fix RouterException to allow for non-logged responses. Change
    RouterException's to only log actual exceptions that should be
    address in bug-fixes. Issue \#125.

1.3.0 (2015-07-29)
------------------

### Features

-   Add WebPush TTL scheme per spec (as of July 28th 2015). Issue \#56.
-   Add WebPush style data delivery with crypto headers to connected
    clients. Each message is stored independently in a new message
    table, with the version and channel id still required to ack a
    message. The version is a UUID4 hex which is also echo'd back to the
    AppServer as a Location URL per the current WebPush spec (as of July
    28th 2015). Issue \#57.
-   Add Sphinx docs with ReadTheDocs publishing. Issue \#98. This change
    also includes a slight Metrics refactoring with a IMetrics
    interface, and renames MetricSink -\> SinkMetrics for naming
    consistency.

### Bug Fixes

-   Increase test coverage of utils for 100% test coverage.
-   Move all dependencies into requirements.txt and freeze them all
    explicitly.

### Internal

-   Refactor proprietary ping handling for modularized dispatch. Issue
    \#82.

    Major changes

    -   RegistrationHandler endpoint is now the sole method for
        registering for a proprietary wake / transport.
    -   `connect` data from websocket hello is ignored.
    -   Unit Testing has been increased to \~ 100% test coverage.
    -   Proprietary Ping and Bridge terminology has been replaced with
        the terms router\_type / router\_data. Router type being one of
        simplepush / apns / gcm and eventually webpush. Router data is
        an arbitrary JSON value as appropriate for the router type.

    db.py

    -   Removed previous methods (deleteByToken/get\_connection/etc) as
        all the router data is included as a single JSON blob for
        DynamoDB to store.
    -   Change register\_user to use UpdateItem to avoid overwriting
        router data when connecting via websocket.

    endpoint.py

    -   EndpointHandler and RegistrationHandler now both inherit from a
        common baseclass: AutoendpointHandler. This baseclass implements
        OPTIONS/HEAD methods, sets the appropriate CORS headers, and has
        several shared error handlers.
    -   A notification has been standardized into a Notification
        namedtuple.
    -   RegistrationHandler API has been changed to have PUT and POST
        methods.
    -   EndpointHandler has been refactored to use the new Router
        interface.
    -   EndpointHandler now uses a basic HMAC auth scheme, GET/PUT with
        existing UAID's require an appropriate HMAC attached with the
        original derived shared key. (Documented in the
        RegistrationHandler.get method)

    websocket.py

    -   Removed use of `connect` data in hello message as
        RegistrationHandler is now the sole method of registering other
        routers.

    router/interface.py (NEW)

    -   IRouter object that all notification routers must implement.
        This handles verifying router data during registration, and is
        responsible for actual delivery of notifications.
    -   RouterException / RouterResponse objects for returning
        appropriate data during register/route\_notification calls.

    router/apnsrouter.py

    -   Moved from bridge/apns.
    -   Refactored to use RouterException/RouterResponse.

    router/gcm.py

    -   Moved from bridge/gcm.
    -   Refactored to use RouterException/RouterResponse.
    -   Removed internal message retries, now returns a 503 in that case
        for the Application Server to retry delivery.

    router/simple.py

    -   Moved code out from endpoint.py.
    -   Refactored existing simplepush routing scheme to use twisted
        inline deferreds to track the logic with less headaches.

### Backward Incompatibilities

-   `bridge` option is now `external_router`.

1.2.3 (2015-06-02)
------------------

### Features

-   Additional logging/metrics on auto-ping and connection aborting.

1.2.2 (2015-05-27)
------------------

### Features

-   Add additional metrics for writers/readers to indicate what twisted
    is still tracking connection-wise.

### Bug Fixes

-   Correct trap for TCP connection closer

1.2.1 (2015-05-20)
------------------

### Bug Fixes

-   Fix error with blank UAIDs being rejected as "already registered"

1.2.0 (2015-05-19)
------------------

### Features

-   Pong delay can no longer be set, and uses an adaptive value based on
    the last ping to try and accurately compensate for higher latency
    connections. This also removes the min\_ping\_interval option such
    that if a client is pinging too frequently we will instead leave
    space for up to the clients timeout of 10-sec (a hardcoded client
    value).

### Bug Fixes

-   Fix 500 errors in endpoint caused by timeouts when trying to deliver
    to expired nodes in the cluster. Resolves Issue \#75.
-   Add CancelledError trap to all deferreds in websocket.py. Resolves
    Issue \#74.
-   Aggressively delete old TCP connections on device reregistration
    (\#72)

### Backwards Incompatibility

-   Removed min\_ping\_interval config option.
-   Removed pong\_delay config option.

1.1rc2 (2015-05-15)
-------------------

### Features

-   Add structured logging output for the endpoint for additional
    request metadata. Resolves Issue \#67.

### Bug Fixes

-   Fix bug with deferreds not being tracked, causing access to objects
    that were cleaned up. Resolves Issue \#66.
-   kill older, duplicate UAID entries that may still be connected.
-   use Websocket Pings to detect dead connections.

1.0rc1 (2015-04-29)
-------------------

### Features

-   Verify ability to read/write DynamoDB tables on startup. Resolves
    Issue \#46.
-   Send un-acknolwedged direct delivery messages to the router if the
    client is disconnected without ack'ing them. Resolves Issue \#36.
-   Use IProducer to more precisely monitor when the client has drained
    the data to immediately resume sending more data. Resolves Issue
    \#28.
-   Add /status HTTP endpoint for autoendpoint. Resolves Issue \#27.
-   Add example stage/prod config files. Resolves Issue \#22.
-   Switch internal routing from requests to twisted http-client.
    Resolves Issue \#21.
-   Add logging for user-agent to metrics tags. Resolves Issue \#20.
-   Add Datadog stats output. Resolves Issue \#17.
-   Add GCM and APNS Bridges. Resolves Issue \#16.
-   Use eliot structured logging for stdout logging that matches ops
    standard for logging. Resolves Issue \#11.
-   Allow storage/router table names to be configurable. Resolves Issue
    \#4.
-   Added optional CORS headers (use --cors to enable). Resolves Issue
    \#3.
-   Add provisioned error metrics to track when throughput is exceeded
    in AWS DynamoDB. Resolves Issue \#2.
-   Add Sentry support (SENTRY\_DSN must be set in the environment).
    Resolves Issue \#1.

### Bug Fixes

-   Capture and log exceptions in websocket protocol functions.
-   Fix bug with 'settings' in cyclone overriding cyclone's settings.
    Resolves Issue \#13.
