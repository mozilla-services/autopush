.. _architecture:

============
Architecture
============

Endpoint nodes handle all notification PUT requests, looking up in DynamoDB to
see what Push server the UAID is connected to. The Endpoint nodes then attempt
delivery to the Push server.

Push connection nodes accept websocket connections (this can easily be HTTP/2
for WebPush), and deliver notifications to connected clients. They check
DynamoDB for missed notifications as necessary.

There will be many more Push servers to handle the connection node, while more
Endpoint nodes can be handled as needed for notification throughput.

Table Rotation
==============

To avoid costly table scans, autopush uses a rotating message and router table.
Clients that haven't connected in 30-60 days will have heir router and message
table entries will dropped and need to re-register.

Tables are post-fixed with the year/month they are meant for, ie:

    messages-2015-02

Tables must be created and have their read/write units properly allocated by a
separate process in advance of the month switch-over as autopush nodes will
assume the tables already exist. Scripts are provided that can be run weekly to
ensure all necessary tables are present, and tables old enough are dropped.

Within a few days of the new month, the load on the prior months table will fall
as clients transition to the new table. The read/write units on the prior
month may then be lowered.

Message Table
-------------

Due to the complexity of having notifications spread across two tables, several
rules are used to avoid losing messages during the month transition.

The logic for connection nodes is more complex, since only the connection node
knows when the client connects, and how many messages it has read through.

A new field will be added to the router table to indicate the last month the
client has read connections through. This is independent of the last_connected
since it is possible for a client to connect, fail to read its notifications,
then reconnect. This field is updated for a new month when the client connects
**after** it has ack'd all the notifications out of the last month.

To avoid issues with time synchronization, the node the client is connected to
acts as the source of truth for when the month has flipped over. Clients are
only moved to the new table on connect, and only after reading/acking all the
notifications for the prior month.

**Rules for Endpoints**

1. Check the router table to see the current_month the client is on.
2. Read the chan list entry from the appropriate month message table to see if
   its a valid channel.

   If its valid, move to step 3.
3. Store the notification in the current months table if valid. (Note that this
   step does not copy the blank entry of valid channels)

**Rules for Connection Nodes**

After Identification:

1. Check to see if the current_month matches the current month, if it does then
   proceed normally using the current months message table.

   If the connection node month does not match stored current_month in the
   clients router table entry, proceed to step 2.
2. Read notifications from prior month and send to client.

   Once all acks are received for all the notifications for that month proceed
   to step 3.
3. Copy the blank message entry of valid channels to the new month message
   table.
4. Update the router table for the current_month.

During switchover, only after the router table update are new commands from the
client accepted.

Handling of Edge Cases:

* Connection node gets more notifications during step 3, enough to buffer, such
  that the endpoint starts storing them in the previous current_month. In this
  case the connection node will check the old table, then the new table to
  ensure it doesn't lose message during the switch.
* Connection node dies, or client disconnects during step 3/4. Not a problem as
  the reconnect will pick it up at the right spot.


Push Characteristics
====================

- When the Push server has sent a client a notification, no further
  notifications will be accepted for delivery (except in one edge case).
  In this state, the Push server will reply to the Endpoint with a 503 to
  indicate it cannot currently deliver the notification. Once the Push
  server has received ack's for all sent notifications, new notifications
  can flow again, and a check of storage will be done if the Push server had
  to reply with a 503. The Endpoint will put the Notification in storage in
  this case.
- (Edge Case) Multiple notifications can be sent at once, if a notification
  comes in during a Storage check, but before it has completed.
- If a connected client is able to accept a notification, then the Endpoint
  will deliver the message to the client completely bypassing Storage. This
  Notification will be referred to as a Direct Notification vs. a Stored
  Notification.
- Provisioned Write Throughput for the Router table determines how many
  connections per second can be accepted across the entire cluster.
- Provisioned Read Throughput for the Router table *and* Provisioned Write
  throughput for the Storage table determine maximum possible notifications
  per second that can be handled. In theory notification throughput can be
  higher than Provisioned Write Throughput on the Storage as connected
  clients will frequently not require using Storage at all. Read's to the
  Router table are still needed for every notification, whether Storage is
  hit or not.
- Provisioned Read Throughput on for the Storage table is an important factor
  in maximum notification throughput, as many slow clients may require frequent
  Storage checks.
- If a client is reconnecting, their Router record will be old. Router records
  have the node_id cleared optimistically by Endpoints when the Endpoint
  discovers it cannot deliver the notification to the Push node on file. If
  the conditional delete fails, it implies that the client has during this
  period managed to connect somewhere again. It's entirely possible that the
  client has reconnected and checked storage before the Endpoint stored the
  Notification, as a result the Endpoint must read the Router table again, and
  attempt to tell the node_id for that client to check storage. Further action
  isn't required, since any more reconnects in this period will have seen the
  stored notification.

Push Endpoint Length
--------------------

The Endpoint URL may seem excessively long. This may seem needless and
confusing since the URL consists of the unique User Agent Identifier (UAID)
and the Subscription Channel Identifier (CHID). Both of these are class 4
Universially Unique Identifiers (UUID) meaning that an endpoint contains
256 bits of entropy (2 * 128 bits). When used in string format, these UUIDs
are always in lower case, dashed format (e.g.
"01234567-0123-abcd-0123-0123456789ab").

Unfortunately, since the endpoint contains an identifier that can be
easily traced back to a specific device, and therefore a specific user,
there is the risk that a user might inadvertently disclose personal
information via their metadata. To prevent this, the server obscures the
UAID and CHID pair to prevent casual determination.

As an example, it is possible for a user to get a Push endpoint for
two different accounts from the same User Agent. If the UAID were disclosed,
then a site may be able to associate a single user to both of those
accounts. In addition, there are reasons that storing the UAID and CHID in
the URL makes operating the server more efficient.

Naturally, we're always looking at ways to improve and reduce the length
of the URL. This is why it's important to store the entire length of the
endpoint URL, rather than try and optimize in some manner.


.. _protocol:

User Agent Protocol Overview
============================

.. Remember to update https://github.com/mozilla-services/push-service/docs/design.md

Autopush uses an older, modified version of the Push protocol called
`SimplePush <http://mozilla-push-service.readthedocs.io/en/latest/design/#simplepush-protocol>`_. This protocol matches WebPush very closely, but is run over WebSocket connections instead of HTTP/2. (See :ref:`websocket_protocol` for the API and code.) This was done for several reasons,
including need to support older services that still ran the older protocol,
as well as lack of HTTP/2 libraries that were suitable for our needs.

This does mean that Autopush does not yet strictly follow the WebPush
specification. This is a brief overview of how the protocol works.

0. Connection
-------------
User Agents establish a WebSocket connection to a well known websocket
URL (usually wss://push.services.mozilla.com). In Firefox, this is defined
in `about:config` as `dom.push.serverURL`.

Once a connection is established, a User Agent must send a "Hello" message.

1. Hello
--------
This is a greeting command allowing a UserAgent to identify itself to the Push service.

`{"messageType": "hello", "uaid": _UAID_, "use_webpush": true}`

*messageType* is the command indicator, in this case, a "hello" command.

*uaid* is the User Agent IDentifier for the User Agent. If none has been
assigned yet, this value is an empty string. If this is not a new connection
this is the previously provided UAID. This value is a UUID4.

*use_webpush* is a flag requesting that the protocol switch to the modern WebPush equivalent.

The response is:

`{"messageType": "hello", "uaid": _UAID_, "status": _status_}`

*UAID* is the assigned User Agent ID. This may differ from the value originally provided by the UserAgent, and MUST override the older value. If the User Agent has any pre-existing subscription registrations, those are now invalid and must be re-registered. This can result in Apps receiving `pushsubscriptionchange` events.

*status* is an HTTP status code indicating success (200) or error.

A *hello* response may be followed by one or more *notification* messages.

2. Register
-----------

When a User Agent needs to provide a new subscription endpoint, it sends a
*register* message.

`{"messageType": "register", "channelID": _channelID_, "key": _publicKey_}`

*channelID* is a UUID4 indicating the channel or subsription ID. It is important that this value be unique across the User Agent.

*key* is the optional public VAPID ECDH encryption key. If this value is specified, then the returned endpoint will be "subscription restricted" and will only accept updates that contain a valid VAPID header associated with that key.

The response is:

`{"messageType": "register", "channelID": _channelID_, "pushEndpoint": _endpointURL_, "status": _status_}`

*channelID* should match the channelID submitted.

*endpointURL* is the URL to send to the Application Server.

*status* is an HTTP status code indicating success (200) or error.

3. Notification
---------------

A Notification message is generated by the Push Service and sent to the User Agent. It contains the data within a push subscription update. It may occur at any time the User Agent is connected.

`{"messageType": "notification", "channelID": _channelID_, "version": _version_,
"data": _data_, "headers": _headers_}`

*channelID* is the channel or subscription ID associated with the update.

*version* is the message version identifier.

*data* is the encrypted body of the subscription update.

*headers* is a dictionary of relevant HTTP headers submitted with the subscription data.

4. ACK / NACK
-------------

As a client processes subscription updates, it may return successful acknowlegements (ACKs) or unsuccesful negative acknoledgements (NACKs/NAKs).

`{"messageType": *ackNak*, "updates": [{"channelID": *channelID*, "version": *version*, "code": *code*}, ...]}`

*ackNak* is either "ack" or "nack" depending on the status of the acknowlegement.

*channelID* is the channel or subscription ID associated with the acknowleged subscription update.

*version* is the message version identifier associated with the acknowleged subscription update.

*code* is the update code corresponding with the acknowlegement

ACK codes
^^^^^^^^^

    :100: Message successfully delivered to Application.

    :101: Message received, but failed to decrypt.

    :102: Message not delivered to application for other reason, (subscription expired, client error, etc.)

NACK codes
^^^^^^^^^^

    :300: RESERVED

    :301: `push` handler threw an uncaught exception

    :302: The promise passed to `pushEvent.waitUntil()` rejected with an error.

    :303: Other error occurred while dispatching the event

.. note::

    Bridged connections (connections that travel across third party networks) may return an `ack` first, and later return a `nack` for the same message. This is due to restrictions imposed by third party networks.

These do not return a response from the Push service


5. Unregister
-----------------

An application may request that a subscription be terminated.

`{"messageType": "unregister", "channelID": *channelID*, "code": *code*}`

*channelID* is the channel or subscription ID to unregister

*code* is the unregistration reason code

Unregister codes
^^^^^^^^^^^^^^^^

    :200: Subscription deleted manually (either via `.unsubscribe()` or by clearing history)

    :201: Unregistered after exceeding quota

    :202: Unregistered because user revoked permission

The response is:

`{"messageType": "unregister", "channelID": *channelID*, "status": *code*}`

*channelID* is the channel associated with the unregistration

*status* is an HTTP status code indicating success (200) or error
