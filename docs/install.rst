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

Autopush uses the `Boto python library`_. Be sure to `properly set up your boto
config file`_.

Python 2.7.7+ w/virtualenv
==========================

You will need ``virtualenv`` installed per the above requirements. Set up your
virtual environment by running the following (if using PyPy, you'll likely need
to specify the ``-p <path to pypy>`` option):

.. code-block:: bash

    $ virtualenv -p `which pypy` .

Then run the Makefile with ``make`` to setup the application.

Configuration files
===================

Autopush can be configured in three ways; by option flags, by environment variables,
and by configuration files. autopush uses three configuration files. These files use
standard `ini` formatting similar to the following:

.. code-block:: cfg

   # A comment description
   ;a_disabled_option
   ;another_disabled_option=default_value
   option=value

Options can either have values or act as boolean flags. If the option is a flag
it is either True if enabled, or False if disabled. The configuration files are
usually richly commented, and you're encouraged to read them to learn how to
set up your installation of autopush.

Please note: any line that does not begin with a `#` or `;` is considered an option
line. if an unexpected option is present in a configuration file, the application
will fail to start.

Configuration files can be located in:

* in the /etc/ directory

* in the configs subdirectory

* in the $HOME or current directory (prefixed by a period '.')

The three configuration files are:

* *autopush_connection.ini* - contains options for use by the websocket handler.
  This file's path can be specifed by the ``--config-connection`` option.

* *autopush_shared.ini* - contains options shared between the connection and
  endpoint handler. This file's path can be specified by the ``--config-shared``
  option.

* *autopush_endpoint.ini* - contains options for the HTTP handlers This file's
  path can be specifed by the ``--config-endpoint`` option.

For instance, if you wished to copy the sample `configs/autopush_connection.ini.sample`
file to `/usr/share/autopush/autopush_connection.ini`, you could then run

.. code-block:: bash

    $ autopush --config-connection=/usr/share/autopush/autopush_connection.ini

to have autopush load configuration information from that file.

Notes on OS X
=============

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

Notes on GCM/FCM support
========================

autopush is capable of routing messages over Google Cloud Messaging/Firebase
Cloud Messaging for android devices. You will need to set up a valid `GCM`_ /
`FCM`_ account. Once you have an account open the Google Developer Console:

* create a new project. Record the Project Number as "SENDER_ID". You will need
  this value for your android application.

* create a new Auth Credential Key for your project. This is available under
  **APIs & Auth** >> **Credentials** of the Google Developer Console. Store
  this value as ``gcm_apikey`` or ``fcm_apikey`` (as appropriate) in
  ``.autopush_endpoint`` server configuration file.

* add ``gcm_enabled`` to the ``.autopush_shared`` server configuration file to
  enable GCM routing.

* add ``fcm_enabled`` to the ``.autopush_shared`` server configuration file to
  enable FCM routing.

Additional notes on using the GCM/FCM bridge are available `on the wiki`_.

.. _`Boto python library`: https://boto.readthedocs.io/en/latest/
.. _`properly set up your boto config file`:
     https://boto.readthedocs.io/en/latest/boto_config_tut.html
.. _`cryptography`: https://cryptography.io/en/latest/installation
.. _`GCM`: http://developer.android.com/google/gcm/index.html
.. _`FCM`: https://firebase.google.com/docs/cloud-messaging/
.. _`on the wiki`: https://github.com/mozilla-services/autopush/wiki/Bridging-Via-GCM
