.. _install:

==========
Installing
==========

System Requirements
===================

Autopush requires the following to be installed. Since each system has different
methods and package names, it's best to search for each package.

* Python 2.7.7 (or later 2.7.x), either
    * PyPy 5.0.1 or later **or**
    * CPython compiled with the following flags:
        * --enable-unicode=usc4 --enable-ipv6
* build-essential (a meta package that includes):
    * autoconf
    * automake
    * gcc
    * make
* pypy **or** python (CPython) development (header files)
* libffi development
* openssl development
* python virtualenv
* git

For instance, if installing on a Fedora or RHEL-like Linux (e.g. an Amazon EC2
instance):

.. code-block:: bash

    $ sudo yum install autoconf automake gcc make libffi-devel \
    openssl-devel pypy pypy-devel python-virtualenv git -y

Or a Debian based system (like Ubuntu):

.. code-block:: bash

    $ sudo apt-get install build-essential libffi-dev \
    libssl-dev pypy-dev python-virtualenv git --assume-yes

Autopush uses the `Boto3 python library`_. Be sure to `properly set up your boto
config file`_.

Notes on OS X
-------------

autopush depends on the Python `cryptography`_ library, which requires
OpenSSL. If you're installing autopush on OS X with a custom version of
OpenSSL, you'll need to set the ``ARCHFLAGS`` environment variable, and add
your OpenSSL library path to ``LDFLAGS`` and ``CFLAGS`` before running
``make``:

.. code-block:: bash

    export ARCHFLAGS="-arch x86_64"
    # Homebrew installs OpenSSL to `/usr/local/opt/openssl` instead of
    # `/usr/local`.
    export LDFLAGS="-L/usr/local/lib" CFLAGS="-I/usr/local/include"

Check-out the Autopush Repository
=================================

You should now be able to check-out the autopush repository.

.. code-block:: bash

    $ git clone https://github.com/mozilla-services/autopush.git

Alternatively, if you're planning on submitting a patch/pull-request to
autopush then fork the repo and follow the *Github Workflow* documented in
`Mozilla Push Service - Code Development`_.

Python 2.7.7+ w/virtualenv
==========================

You will need ``virtualenv`` installed per the above requirements. Set up your
virtual environment by running the following (if using PyPy, you'll likely need
to specify the ``-p <path to pypy>`` option):

.. code-block:: bash

    $ virtualenv -p `which pypy` .

Then run the Makefile with ``make`` to setup the application.

Scripts
=======

After installation of autopush the following command line utilities are
available in the virtualenv ``bin/`` directory:

=======================    ===========
``autopush``               Runs a Connection Node
``autoendpoint``           Runs an Endpoint Node
``endpoint_diagnostic``    Runs Endpoint diagnostics
``autokey``                Endpoint encryption key generator
=======================    ===========

You will need to have a `boto config file`_ file or ``AWS`` environment keys
setup before the first 3 utilities will run properly.

Building Documentation
======================

To build the documentation, you will need additional packages installed:

.. code-block:: bash

    $ pip install -r doc-requirements.txt

You can then build the documentation:

.. code-block:: bash

    $ cd docs
    $ make html

Using a Local DynamoDB Server
=============================

Amazon supplies a `Local DynamoDB Java server`_ to use for local testing that
implements the complete DynamoDB API. This is used for automated unit testing
on Travis and can be used to run autopush locally for testing.

You will need the Java JDK 6.x or newer.

To setup the server locally:

.. code-block:: bash

    $ mkdir ddb
    $ curl -sSL http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.tar.gz | tar xzvC ddb/
    $ java -Djava.library.path=./ddb/DynamoDBLocal_lib -jar ./ddb/DynamoDBLocal.jar -sharedDb -inMemory

An example `boto config file`_ is provided in ``automock/boto.cfg`` that
directs autopush to your local DynamoDB instance.

.. _Mozilla Push Service - Code Development: http://mozilla-push-service.readthedocs.io/en/latest/development/#code-development
.. _`boto config file`: http://boto3.readthedocs.io/en/docs/guide/quickstart.html#configuration
.. _`Local DynamoDB Java server`: http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tools.DynamoDBLocal.html
.. _`Boto3 python library`: https://boto3.readthedocs.io/en/latest/
.. _`properly set up your boto config file`: http://boto3.readthedocs.io/en/docs/guide/quickstart.html#configuration
.. _`cryptography`: https://cryptography.io/en/latest/installation


Configuring for Third Party Bridge services:

.. toctree::
    :maxdepth: 1

    apns.rst
    adm.rst
