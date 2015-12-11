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
256 bits of entropy (2 * 128 bits).

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
