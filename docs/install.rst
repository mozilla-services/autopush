.. _install:

==========
Installing
==========

System Requirements
===================

Autopush requires the following to be installed. Since each system has different
methods and package names, it's best to search for each package.

* python 2.7.7 (or later) with the following flags set:
    * --enable-unicode=usc4 --enable-ipv6
* build-essentials (a meta package that includes:
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

Autopush uses the `Boto python library <https://boto.readthedocs.io/en/latest/>`_. Be sure to `properly set up <https://boto.readthedocs.io/en/latest/boto_config_tut.html>`_ your boto configuration file.

Python 2.7.7+ w/virtualenv
==========================

You will need ``virtualenv`` installed per the above requirements. Set up your virtual environment by running

.. code-block:: bash

    $ virtualenv .

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

Notes on GCM/FCM support
====================
autopush is capable of routing messages over Google Cloud Messaging/Firebase Cloud Messaging for android
devices. You will need to set up a valid `GCM <http://developer.android.com/google/gcm/index.html>`_ / `FCM <https://firebase.google.com/docs/cloud-messaging/>`_ account. Once you have an account open the Google Developer Console:

* create a new project. Record the Project Number as "SENDER_ID". You will need this value for your android application.
* create a new Auth Credential Key for your project. This is available under **APIs & Auth** >> **Credentials** of the Google Developer Console. Store this value as ``gcm_apikey`` or ``fcm_apikey`` (as appropriate) in ``.autopush_endpoint`` server configuration file.
* add ``gcm_enabled`` to the ``.autopush_shared`` server configuration file to enable GCM routing.
* add ``fcm_enabled`` to the ``.autopush_shared`` server configuration file to enable FCM routing.

Additional notes on using the GCM/FCM bridge are available `on the wiki <https://github.com/mozilla-services/autopush/wiki/Bridging-Via-GCM>`_.
