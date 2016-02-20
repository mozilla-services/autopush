.. _http:

HTTP Endpoints for Notifications
================================

Autopush exposes three HTTP endpoints:

`/push/...`

This is tied to :class:`EndpointHandler` (:ref:`endpoint_module`). This endpoint is returned by the Push registration process and is used by the :term:`AppServer` to send Push alerts
to the Application. See :ref:`send`.

`/m/...`

This is tied to :class:`MessageHandler` (:ref:`endpoint_module`). This endpoint handles individual
message operations on messages pending delivery, such as deleting the
message or updating the contents or Time To Live (TTL). See :ref:`cancel`
and :ref:`update`.

`/v1/.../.../registration/...`

This is tied to the :class:`RegistrationHandler` (:ref:`endpoint_module`). This endpoint is used by
apps that wish to use :term:`bridging` protocols to register new channels.
See :ref:`bridge_api`.

---

.. _http_api:

Push Service HTTP API
=====================

The following section describes how remote servers can send Push
Notifications to apps running on remote User Agents.

API methods requiring Authorization must provide the Authorization
header containing the authrorization token. The Authorization token is returned
as "secret" in the registration response.

Lexicon
-------

   :{UAID}: The Push User Agent Registration ID

Push assigns each remote recipient a unique identifier. This value is
assigned during **Registration**

   :{CHID}: The :term:`Channel` Subscription ID

Push assigns a unique identifier for each subscription for a given {UAID}.
This value is assigned during **Channel Subscription**

   :{message-id}: The unique Message ID

Push assigns each message for a given Channel Subscription a unique
identifier. This value is assigned during **Send Notification**

Response
--------

The responses will be JSON formatted objects. In addition, API calls
will return valid HTTP error codes (see :ref:`errors` sub-section for
descriptions of specific errors).

For non-success responses, an extended error code object will be
returned with the following format:

.. code-block:: json

    {
        "code": 404,  // matches the HTTP status code
        "errno": 103, // stable application-level error number
        "error": "Not Found", // string representation of the status
        "message": "No message found" // optional additional error information
    }


.. _errors:

Error Codes
-----------

Unless otherwise specified, all calls return the following error codes:

-  20x - Success
-  301 - Moved + `Location:` if `{token}` is invalid (Bridge API Only)
-  400 - Bad Parameters

   - errno 101 - Missing neccessary crypto keys
   - errno 102 - Invalid URL endpoint
   - errno 108 - Router type is invalid
   - errno 110 - Invalid crypto keys specified
   - errno 111 - Missing Required Header

       - Missing TTL Header - Include the Time To Live header (`IETF WebPush protocol §6.2 <https://tools.ietf.org/html/draft-ietf-webpush-protocol#section-6.2>`_)
       - Missing Crypto Headers - Include the appropriate encryption headers (`WebPush Encryption §3.2 <https://webpush-wg.github.io/webpush-encryption/#rfc.section.3.2>`_ and `WebPush VAPID §4 <https://martinthomson.github.io/webpush-vapid/#rfc.section.4>`_)

-  401 - Bad Authorization

   - errno 109 - Invalid authentication

-  410 - `{UAID}` or `{CHID}` not found

   - errno 103 - Expired URL endpoint
   - errno 105 - Endpoint became unavailable during request
   - errno 106 - Invalid subscription

-  413 - Payload too large

   - errno 104 - Data payload too large

-  500 - Unknown server error

   - errno 999 - Unknown error

-  503 - Server temporarily unavaliable.

   -  errno 201 - Use exponential back-off for retries
   -  errno 202 - Immediate retry ok

Calls
-----

.. _send:

Send Notification
~~~~~~~~~~~~~~~~~

Send a notification to the given endpoint identified by it's `token`.

**Call:**

.. http:put:: /push/{token}

    If the client is using webpush style data delivery, then the body in its
    entirety will be regarded as the data payload for the message per
    `the WebPush spec
    <https://tools.ietf.org/html/draft-thomson-webpush-http2-02#section-5>`_.

    .. note::

        Some bridged connections require data transcription and may limit the
        length of data that can be sent. For instance, using a GCM bridge
        will require that the data be converted to base64. This means that
        data may be limited to only 2744 bytes instead of the normal 4096
        bytes.

**Parameters:**

    :form version: (*Optional*) Version of notification, defaults to current
                   time

**Reply:**

.. code-block:: json

    {"message-id": {message-id}}

**Return Codes:**

    :statuscode 404: `token` is invalid.
    :statuscode 202: Message stored for delivery to client at a later
                     time.
    :statuscode 200: Message delivered to node client is connected to.

.. _cancel:

Cancel Notification
~~~~~~~~~~~~~~~~~~~

Delete the message given the `message_id`.

**Call:**

.. http:delete:: /m/{message_id}

**Parameters:**


    None

**Reply:**


.. code-block:: json

    {}

**Return Codes:**


    See :ref:`errors`.


.. _update:

Update Notification
~~~~~~~~~~~~~~~~~~~

Update the message at the given `{message_id}`.


**Call:**


.. http:put:: /m/(string/message_id)

**Parameters:**

    This method takes the same arguments as WebPush PUT, with values
    replacing that for the provided message.

    .. note::

        In the rare condition that the client is online, and has recieved
        the message but has not acknowledged it yet; then it is possible that
        the client will not get the updated message until reconnect. This
        should be considered a rare edge-case.

**Reply:**

.. code-block:: json

    {}

**Return Codes:**

    :statuscode 404: `message_id` is not found.
    :statuscode 200: Message has been updated.

---

.. _bridge_api:

Push Service Bridge HTTP Interface
==================================

Push allows for remote devices to perform some functions using an HTTP
interface. This is mostly used by devices that are bridging via an
external protocol like
`GCM <https://developers.google.com/cloud-messaging/>`__ or
`APNs <https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Introduction.html#//apple_ref/doc/uid/TP40008196-CH1-SW1>`__. All message bodies must be UTF-8 encoded.

Lexicon
-------

For the following call definitions:

   :{type}: The bridge type.

Allowed bridges are `gcm` (Google Cloud Messaging) and `apns` (Apple
Push Notification system)

   :{token}: The bridge specific public exchange token

Each protocol requires a unique token that addresses the remote application.
For GCM, this is the `SenderID` and is pre-negotiated outside of the push
service.

   :{instanceid}: The bridge specific private identifier token

Each protocol requires a unique token that addresses the
application on a given user's device. This is usually the product of the
application registering the {instanceid} with the native bridge protocol
agent.

   :{auth_token}: The Authorization token

Most calls to the HTTP interface require a Authorization header. The
Authorization header is a bearer token, which has been provided by the
**Registration** call and is preceded by the token type word "Bearer".

An example of the Authorization header would be:

::

    Authorization: Bearer 0123abcdef

Calls
-----

Registration
~~~~~~~~~~~~

Request a new UAID registration, Channel ID, and optionally set a bridge
type and token for this connection.

**Call:**


.. http:post:: /v1/{type}/{token}/registration

This call requires no Authorization for first time use.

**Parameters:**


    {"token":{instanceid}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

**Reply:**


.. code-block:: json

    `{"uaid": {UAID}, "secret": {auth_token},
    "endpoint": "https://updates-push...", "channelID": {CHID}}`

example:

.. code-block:: http

    > POST /v1/gcm/a1b2c3/registration
    >
    > {"token": "1ab2c3"}

.. code-block:: json

    < {"uaid": "abcdef012345",
    < "secret": "0123abcdef",
    < "endpoint": "https://updates-push.services.mozaws.net/push/...",
    < "channelID": "01234abcd"}

**Return Codes:**


See :ref:`errors`.

Token updates
~~~~~~~~~~~~~

Update the current bridge token value

**Call:**


.. http:put:: /v1/{type}/{token}/registration/{uaid}

::

    Authorization: Bearer {auth_token}

**Parameters:**


    {"token": {instanceid}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

**Reply:**


.. code-block:: json

    {}

example:

.. code-block:: http

    > PUT /v1/gcm/a1b2c3/registration/abcdef012345
    > Authorization: Bearer 0123abcdef
    >
    > {"token": "5e6g7h8i"}

.. code-block:: json

    < {}

**Return Codes:**


See :ref:`errors`.

Channel Subscription
~~~~~~~~~~~~~~~~~~~~

Acquire a new ChannelID for a given UAID.

**Call:**


.. http:post:: /v1/{type}/{token}/registration/{uaid}/subscription

::

    Authorization: Bearer {auth_token}

**Parameters:**


     {}

**Reply:**


.. code-block:: json

    {"channelID": {CHID}, "endpoint": "https://updates-push..."}

example:

.. code-block:: http

    > POST /v1/gcm/a1b2c3/registration/abcdef012345/subscription
    > Authorization: Bearer 0123abcdef
    >
    > {}

.. code-block:: json

    < {"channelID": "43210efgh"
    < "endpoint": "https://updates-push.services.mozaws.net/push/..."}

**Return Codes:**


See :ref:`errors`.

Unregister UAID (and all associated ChannelID subscriptions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Indicate that the UAID, and by extension all associated subscriptions,
is no longer valid.

**Call:**


.. http:delete:: /v1/{type}/{token}/registration/{uaid}

::

    Authorization: Bearer {auth_token}

**Parameters:**


    {}

**Reply:**

.. code-block:: json

    {}

**Return Codes:**

See :ref:`errors`.

Unsubscribe Channel
~~~~~~~~~~~~~~~~~~~

Remove a given ChannelID subscription from a UAID.

**Call:**

.. http:delete:: /v1/{type}/{token}/registration/{UAID}/subscription/{CHID}

::

    Authorization: Bearer {auth_token}

**Parameters:**

    {}

**Reply:**


.. code-block:: json

    {}

**Return Codes:**

See :ref:`errors`.
