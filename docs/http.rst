.. _http:

HTTP Endpoints for Notifications
================================

Autopush exposes three HTTP endpoints:

`/push/...`

This is tied to :class:`EndpointHandler` (:ref:`endpoint_module`). This endpoint is returned by the Push registration process and is used by the
:term:`AppServer` to send Push alerts to the Application. See :ref:`send`.

`/m/...`

This is tied to :class:`MessageHandler` (:ref:`endpoint_module`). This
endpoint handles individual
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

Lexicon
-------

   :{UAID}: The Push User Agent Registration ID

Push assigns each remote recipient a unique identifier. {UAID}s are UUIDs in
lower case, dashed format. (e.g. '01234567-abcd-abcd-abcd-012345678abc') This value is assigned during **Registration**

   :{CHID}: The :term:`Channel` Subscription ID

Push assigns a unique identifier for each subscription for a given {UAID}.
Like {UAID}s, {CHID}s are UUIDs in lower case, dashed format.
This value is assigned during **Channel Subscription**

   :{message-id}: The unique Message ID

Push assigns each message for a given Channel Subscription a unique
identifier. This value is assigned during **Send Notification**

.. _error_resp:

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

Autopush uses error codes based on `HTTP response codes <https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html>`_.
An error response will contain a JSON body including an additional error
information (see :ref:`error_resp`).

Unless otherwise specified, all calls return one the following error statuses:

-  20x - **Success** - The message was accepted for transmission to the client. Please note that the message may still be rejected by the User Agent if there is an error with the message's encryption.
-  301 - **Moved + `Location:`** if `{client_token}` is invalid (Bridge API Only) - Bridged services (ones that run over third party services like GCM and APNS), may require a new URL be used. Please stop using the old URL immediately and instead use the new URL provided.
-  400 - **Bad Parameters** -- One or more of the parameters specified is invalid. See the following sub-errors indicated by `errno`

   - errno 101 - Missing necessary crypto keys - One or more required crypto key elements are missing from this transaction. Refer to the `appropriate specification <https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/>`_ for the requested content-type.
   - errno 108 - Router type is invalid - The URL contains an invalid router type, which may be from URL corruption or an unsupported bridge. Refer to :ref:`bridge_api`.
   - errno 110 - Invalid crypto keys specified - One or more of the crytpo key elements are invalid. Refer to the `appropriate specification <https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/>`_ for the requested content-type.
   - errno 111 - Missing Required Header - A required crypto element header is missing. Refer to the `appropriate specification <https://datatracker.ietf.org/doc/draft-ietf-httpbis-encryption-encoding/>`_ for the requested content-type.

       - Missing TTL Header - Include the Time To Live header (`IETF WebPush protocol §6.2 <https://tools.ietf.org/html/draft-ietf-webpush-protocol#section-6.2>`_)
       - Missing Crypto Headers - Include the appropriate encryption headers (`WebPush Encryption §3.2 <https://webpush-wg.github.io/webpush-encryption/#rfc.section.3.2>`_ and `WebPush VAPID §4 <https://tools.ietf.org/html/draft-ietf-webpush-vapid-02#section-4>`_)

   - errno 112 - Invalid TTL header value - The Time To Live "TTL" header contains an invalid or unreadble value. Please change to a number of seconds that this message should live, between 0 (message should be dropped immediately if user is unavailable) and 2592000 (hold for delivery within the next approximately 30 days).
   - errno 113 - Invalid Topic header value - The Topic header contains an invalid or unreadble value. Please use only ASCII alphanumeric values [A-Za-z0-9].

-  401 - **Bad Authorization** - `Authorization` header is invalid or missing. See the `VAPID specification <https://datatracker.ietf.org/doc/draft-ietf-webpush-vapid/>`_.

   - errno 109 - Invalid authentication

- 404 - **Endpoint Not Found** - The URL specified is invalid and should not be used again.

   - errno 102 - Invalid URL endpoint

-  410 - **Endpoint Not Valid** - The URL specified is no longer valid and should no longer be used. A User may have cancelled their subscription or otherwise become unavailable.

   - errno 103 - Expired URL endpoint
   - errno 105 - Endpoint became unavailable during request
   - errno 106 - Invalid subscription

-  413 - **Payload too large** - The body of the message to send is too large. The max data that can be sent is 4028 characters. Please reduce the size of the message.

   - errno 104 - Data payload too large

-  500 - **Unknown server error** - An internal error occurred within the Push Server.

   - errno 999 - Unknown error

-  503 - **Server temporarily unavaliable.** - The Push Service is currently unavailable. See the error number "errno" value to see if retries are available.

   -  errno 201 - Use exponential back-off for retries
   -  errno 202 - Immediate retry ok

Calls
-----

.. _send:

Send Notification
~~~~~~~~~~~~~~~~~

Send a notification to the given endpoint identified by its `push_endpoint`.
Please note, the Push endpoint URL (which is what is used to send notifications)
should be considered "opaque". We reserve the right to change any portion
of the Push URL in future provisioned URLs.

**Call:**

.. http:put:: {push_endpoint}

    If the client is using webpush style data delivery, then the body in its
    entirety will be regarded as the data payload for the message per
    `the WebPush spec
    <https://tools.ietf.org/html/draft-thomson-webpush-http2-02#section-5>`_.

    .. note::

        Some bridged connections require data transcription and may limit the
        length of data that can be sent. For instance, using a GCM/FCM bridge
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

    :statuscode 404: Push subscription is invalid.
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
`GCM <https://developers.google.com/cloud-messaging/>`__/`FCM <https://firebase.google.com/docs/cloud-messaging/>`__ or
`APNs <https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Introduction.html#//apple_ref/doc/uid/TP40008196-CH1-SW1>`__. All message bodies must be UTF-8 encoded.

API methods requiring Authorization must provide the Authorization
header containing the registration secret. The registration secret is
returned as "secret" in the registration response.

Lexicon
-------

For the following call definitions:

   :{type}: The bridge type.

Allowed bridges are `gcm` (Google Cloud Messaging), `fcm` (Firebase Cloud
Messaging), and `apns` (Apple Push Notification system)

   :{app_id}: The bridge specific application identifier

Each bridge may require a unique token that addresses the remote application
For GCM/FCM, this is the `SenderID` (or 'project number') and is pre-negotiated outside of the push
service. You can find this number using the
`Google developer console <https://console.developers.google.com/iam-admin/settings/project>`__.
For APNS, this value is the "platform" or "channel" of development (e.g.
"firefox", "beta", "gecko", etc.)
For our examples, we will use a client token of
"33clienttoken33".

   :{instance_id}: The bridge specific private identifier token

Each bridge requires a unique token that addresses the
application on a given user's device. This is the
"`Registration Token <https://firebase.google.com/docs/cloud-messaging/android/client#sample-register>`__" for
GCM/FCM or "`Device Token <https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/IPhoneOSClientImp.html#//apple_ref/doc/uid/TP40008194-CH103-SW2>`__"
for APNS. This is usually the product of the
application registering the {instance_id} with the native bridge via the user
agent. For our examples, we will use an instance ID of "11-instance-id-11".

   :{secret}: The registration secret from the Registration call.

Most calls to the HTTP interface require a Authorization header. The
Authorization header is a simple bearer token, which has been provided by the
**Registration** call and is preceded by the scheme name "Bearer". For
our examples, we will use a registration secret of "00secret00".

An example of the Authorization header would be:

::

    Authorization: Bearer 00secret00

Calls
-----

Registration
~~~~~~~~~~~~

Request a new UAID registration, Channel ID, and optionally set a bridge
type and 3rd party bridge instance ID token for this connection.

**Call:**


.. http:post:: /v1/{type}/{app_id}/registration

This call requires no Authorization header for first time use.

**Parameters:**


    {"token":{instance_id}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

**Reply:**


.. code-block:: json

    `{"uaid": {UAID}, "secret": {secret},
    "endpoint": "https://updates-push...", "channelID": {CHID}}`

example:

.. code-block:: http

    > POST /v1/fcm/33clienttoken33/registration
    >
    > {"token": "11-instance-id-11"}

.. code-block:: json

    < {"uaid": "01234567-0000-1111-2222-0123456789ab",
    < "secret": "00secret00",
    < "endpoint": "https://updates-push.services.mozaws.net/push/...",
    < "channelID": "00000000-0000-1111-2222-0123456789ab"}

**Return Codes:**


See :ref:`errors`.

Token updates
~~~~~~~~~~~~~

Update the current bridge token value. Note, this is a ***PUT*** call, since
we are updating existing information.

**Call:**


.. http:put:: /v1/{type}/{app_id}/registration/{uaid}

::

    Authorization: Bearer {secret}

**Parameters:**


    {"token": {instance_id}}

    .. note::

        If additional information is required for the bridge, it may be
        included in the paramters as JSON elements. Currently, no additional
        information is required.

**Reply:**


.. code-block:: json

    {}

example:

.. code-block:: http

    > PUT /v1/fcm/33clienttoken33/registration/abcdef012345
    > Authorization: Bearer 00secret00
    >
    > {"token": "22-instance-id-22"}

.. code-block:: json

    < {}

**Return Codes:**


See :ref:`errors`.

Channel Subscription
~~~~~~~~~~~~~~~~~~~~

Acquire a new ChannelID for a given UAID.

**Call:**


.. http:post:: /v1/{type}/{app_id}/registration/{uaid}/subscription

::

    Authorization: Bearer {secret}

**Parameters:**


     {}

**Reply:**


.. code-block:: json

    {"channelID": {CHID}, "endpoint": "https://updates-push..."}

example:

.. code-block:: http

    > POST /v1/fcm/33clienttoken33/registration/abcdef012345/subscription
    > Authorization: Bearer 00secret00
    >
    > {}

.. code-block:: json

    < {"channelID": "01234567-0000-1111-2222-0123456789ab",
    < "endpoint": "https://updates-push.services.mozaws.net/push/..."}

**Return Codes:**


See :ref:`errors`.

Unregister UAID (and all associated ChannelID subscriptions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Indicate that the UAID, and by extension all associated subscriptions,
is no longer valid.

**Call:**


.. http:delete:: /v1/{type}/{app_id}/registration/{uaid}

::

    Authorization: Bearer {secret}

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

.. http:delete:: /v1/{type}/{app_id}/registration/{UAID}/subscription/{CHID}

::

    Authorization: Bearer {secret}

**Parameters:**

    {}

**Reply:**


.. code-block:: json

    {}

**Return Codes:**

See :ref:`errors`.
