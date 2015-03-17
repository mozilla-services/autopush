========
AutoPush
========

.. image:: https://travis-ci.org/mozilla-services/autopush.svg?branch=master
    :target: https://travis-ci.org/mozilla-services/autopush

.. image:: https://coveralls.io/repos/mozilla-services/autopush/badge.svg
  :target: https://coveralls.io/r/mozilla-services/autopush

*A simple prototype SimplePush style service utilizing AWS extensively.*

Ok, that's not entirely accurate. This is a mostly production-ready Push
system utilizing DynamoDB extensively. It was created to test out some
architecture changes and get a better understanding of underlying concurrency
issues related to moving notifications around.

Installing
==========

You will first need to get pypy as appropriate for your system and put it's
uncompressed folder in the autopush directory as ``pypy``.

PyPy downloads can be found here: http://pypy.org/download.html#default-with-a-jit-compiler

Once you have downloaded, decompressed, and renamed this to ``pypy``, you can
run the Makefile with ``make``, which will setup the application.

Running
=======

There are two programs that will have scripts setup after installing (In the
``pypy/bin/`` directory):

- ``autopush``
- ``autoendpoint``

You will need to have a ``~/.boto`` file or ``AWS`` environment keys setup
before either of these will run properly. By default they will create a router
and storage DynamoDB table named ``storage`` and ``router`` with provisioned
throughputs of ``1``.

You can then test that this works by using the `simplepush tester <https://github.com/mozilla-services/simplepush_test>`_, like so:

.. code-block:: bash

    ~/simplepush_test/ $ PUSH_SERVER=ws://localhost:8080/ ./bin/nosetests

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
- (Edge Case) It's possible due to timing, that if the Endpoint gets a 503,
  the Push server could query Storage for 'missed notifications' before the
  Endpoint has written it. To address this, when an Endpoint gets a 503, it
  should store the message first, then inform the Push server to check for
  Stored notifications.
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
- If a connected client hasn't ACK'd notifications, all new notifications
  will have their data dropped and go to storage. This is to avoid excessive
  memory costs for Push servers, since holding large connection counts is
  already RAM intensive.
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
