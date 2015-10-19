.. _install:

==========
Installing
==========

System Requirements
===================

Autopush requires the following to be installed. Since each system has different
methods and package names, it's best to search for each package.

* autoconf
* automake
* gcc
* make
* libffi development
* libncurses5 development
* openssl development
* patch
* python development
* python virtualenv
* readline development

For instance, if installing on an Amazon EC2 machine:

.. code-block:: bash

    $ sudo yum install autoconf automake gcc make libffi-devel \
    libncurses5-devel openssl-devel patch python-devel \
    python-virtualenv readline-devel -y

Autopush uses the `Boto python library <http://boto.readthedocs.org/en/latest/>`_. Be sure to `properly set up <http://boto.readthedocs.org/en/latest/boto_config_tut.html>`_ your ``.boto`` configuration file.

Python 2.7.7+ w/virtualenv
==========================

You will need ``virtualenv`` installed per the above requirements. Set up your virtual environment by running

.. code-block:: bash

    $ virutalenv .

Then run the Makefile with ``make`` to setup the application.

Notes on OS X
=============

autopush depends on the Python `cryptography <https://cryptography.io/en/latest/installation>`_
library, which requires OpenSSL. If you're installing autopush on OS X
with a custom version of OpenSSL, you'll need to set the ``ARCHFLAGS``
environment variable, and add your OpenSSL library path to ``LDFLAGS`` and
``CFLAGS`` before running ``make``:

.. code-block:: bash

    export ARCHFLAGS="-arch x86_64"
    # Homebrew installs OpenSSL to `/usr/local/opt/openssl` instead of
    # `/usr/local`.
    export LDFLAGS="-L/usr/local/lib" CFLAGS="-I/usr/local/include"

Notes on GCM support
====================
autopush is capable of routing messages over Google Cloud Messaging for android
devices. You will need to set up a valid GCM `account <http://developer.android.com/google/gcm/index.html>`_. Once you have an account open the Google Developer Console:

* create a new project. Record the Project Number as "SENDER_ID". You will need this value for your android application.
* create a new Auth Credential Key for your project. This is available under **APIs & Auth** >> **Credentials** of the Google Developer Console. Store this value as ``gcm_apikey`` in ``.autopush_endpoint`` server configuration file.
* add ``external_router=t`` to the ``.autopush_endpoint`` server configuration file to enable GCM routing.

Additional notes on using the GCM bridge are available `on the wiki <https://github.com/mozilla-services/autopush/wiki/Bridging-Via-GCM>`_.
