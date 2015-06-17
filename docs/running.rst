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

Using a Moto Mock Server
========================

To use a mock DynamoDB server (and run entirely locally), first install
``moto`` with pip, and run a dynamodb moto server:

.. code-block:: bash

    $ ./pypy/bin/pip install moto
    $ ./pypy/bin/moto_server dynamodb2 -p 5000
    $ cp automock/boto.cfg ~/.boto

Note the last line copies a boto config over ``~/.boto`` in your home dir. If
you have existing AWS Credentials in this file, you should move it elsewhere
first before running ``autopush`` and ``autoendpoint``.
