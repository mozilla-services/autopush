.. _running:

================
Running Autopush
================

There are two programs that will have scripts setup after installing (In the
``pypy/bin/`` directory):

- ``autopush``
- ``autoendpoint``

You will need to have a ``~/.boto`` file or ``AWS`` environment keys setup
before either of these will run properly. By default they will create a router
and storage DynamoDB table named ``storage`` and ``router`` with provisioned
throughputs of ``5``.

You can then test that this works by using the `simplepush tester
<https://github.com/mozilla-services/simplepush_test>`_, like so:

.. code-block:: bash

    ~/simplepush_test/ $ PUSH_SERVER=ws://localhost:8080/ ./bin/nosetests

Using a Local DynamoDB Server
=============================

Amazon supplies a `Local DynamoDB Java server
<http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tools.DynamoDBLocal.html>`_
to use for local testing that implements the complete DynamoDB API. This is used
for automated unit testing on Travis and can be used to run autopush locally for
testing.

You will need the Java JDK 6.x or newer.

To setup the server locally:

.. code-block:: bash

    $ mkdir ddb
    $ curl -sSL http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.tar.gz | tar xzvC ddb/
    $ java -Djava.library.path=./ddb/DynamoDBLocal_lib -jar ./ddb/DynamoDBLocal.jar -sharedDb -inMemory
    $ cp automock/boto.cfg ~/.boto

Note the last line copies a boto config over ``~/.boto`` in your home dir. If
you have existing AWS Credentials in this file, you should move it elsewhere
first before running ``autopush`` and ``autoendpoint``.
