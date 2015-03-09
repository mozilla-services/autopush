========
AutoPush
========

*A simple prototype SimplePush style service utilizing AWS extensively.*

Ok, that's not entirely accurate. This is a mostly production-ready Push
system utilizing DynamoDB extensively. It was created to test out some
architecture changes and get a better understanding of underlying concurrency
issues related to moving notifications around.

Push Architecture
=================

Endpoint nodes handle all notification PUT requests, looking up in DynamoDB to
see what Push server the UAID is connected to. The Endpoint nodes then attempt
delivery to the Push server.

Push server's accept websocket connections (this can easily be HTTP/2 for
WebPush), and deliver notifications to connected clients. They check DynamoDB
for missed notifications as necessary.

There will be many more Push servers to handle the connection node, while more
Endpoint nodes can be handled as needed for notification throughput.

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
- (Edge Case, UNRESOLVED) It's possible due to timing, that if the Endpoint
  gets a 503, the Push server could query Storage for 'missed notifications'
  before the Endpoint has written it.
  Possible Solution: Have the Endpoint use a new Push server call to flag
  a notification check *after* its Storage call has completed.
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
- If a connected client hasn't ACK'd notifications, all new notifications
  will have their data dropped and go to storage. This is to avoid excessive
  memory costs for Push servers, since holding large connection counts is
  already RAM intensive.

