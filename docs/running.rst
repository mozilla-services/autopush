.. _running:

================
Running Autopush
================

Overview
========

To run Autopush, you will need to run at least one connection node, one endpoint
node, and a local DynamoDB server or AWS DynamoDB. The prior section on
Autopush architecture documented these components and their relation to each
other.

The recommended way to run the latest development or tagged Autopush release is
to use `docker`_. Autopush has `docker`_ images built automatically for every
tagged release and when code is merged to master.

If you want to run the latest Autopush code from source then you should follow
the :ref:`developing` instructions.

The instructions below assume that you want to run Autopush with a local
DynamoDB server for testing or local verification. The docker containers can
be run on separate hosts as well, or with AWS DynamoDB instead.

Setup
=====

These instructions will yield a locally running Autopush setup with the
connection node listening on localhost port ``8080``, with the endpoint node
listening on localhost port ``8082``. Make sure these ports are available on
localhost before running, or change the configuration to have the Autopush
daemons use other ports.

1. Install `docker`_
2. Install `docker-compose`_
3. Create a directory for your docker and Autopush configuration:

    .. code-block:: bash

        $ mkdir autopush-config
        $ cd autopush-config

4. Fetch the latest ``docker-compose.yml`` file:

    .. code-block:: bash

        $ curl -O https://raw.githubusercontent.com/mozilla-services/autopush/master/docker-compose.yml

5. Fetch the latest ``boto-compose.cfg`` file:

    .. code-block:: bash

        $ curl -O https://raw.githubusercontent.com/mozilla-services/autopush/master/boto-compose.cfg

The ``boto-compose.cfg`` file will be mounted inside the Autopush docker
containers when running to point Autopush at the locally running DynamoDB

.. note::

    The docker images used take approximately 1.5 GB of disk-space, make sure
    you have appropriate free-space before proceeding.

Generate a Crypto-Key
---------------------

As the :ref:`cryptography` section notes, you will need a ``CRYPTO_KEY`` to
run both of the Autopush daemons. To generate one with the docker image:

.. code-block:: bash

    $ docker run -t -i bbangert/autopush autokey
    Key = hkclU1V37Dnp-0DMF9HLe_40Nnr8kDTYVbo2yxuylzk=

Store the key for later use (including the trailing ``=``).

Start Autopush
==============

Once you've completed the setup and have a crypto key, you can run a local
Autopush with a single command:

.. code-block:: bash

    $ CRYPTO_KEY=hkclU1V37Dnp-0DMF9HLe_40Nnr8kDTYVbo2yxuylzk= docker-compose up

`docker-compose`_ will start up three containers, two for each Autopush daemon,
and a third for DynamoDB.

By default, the following services will be exposed:

``ws://localhost:8080/`` - websocket server

``http://localhost:8082/`` - HTTP Endoint Server (See :ref:`the HTTP API <http>`)

You could set the ``CRYPTO_KEY`` as an environment variable, or setup a more
thorough configuration using config files as documented below.

The load-tester can be run against it or you can run Firefox with the
local Autopush per the :ref:`test-with-firefox` docs.

Configuration
=============

Autopush can be configured in three ways; by option flags, by environment variables,
and by configuration files. Autopush uses three configuration files. These files use
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

Sample Configurations
---------------------

Three sample configurations, a base config, and a config for each Autopush
daemon can be found at https://github.com/mozilla-services/autopush/tree/master/config

These can be downloaded and modified as desired.

Config Files with Docker
------------------------

To use a configuration file with `docker`_, ensure the config files are
accessible to the user running `docker-compose`_. Then you will need to update
the ``docker-compose.yml`` to use the config files and make them available to
the appropriate docker containers.

Mounting a config file to be available in a docker container is fairly simple,
for instance, to mount a local file ``autopush_connection.ini`` into a container
as ``/etc/autopush_connection.ini``, update the ``autopush`` section of the
``docker-compose.yml`` to be:

.. code-block:: yaml

    volumes:
      - ./boto-compose.cfg:/etc/boto.cfg:ro
      - ./autopush_connection.ini:/etc/autopush_connection.ini

Autopush automatically searches for a configuration file at this location so
nothing else is needed.

Notes on GCM/FCM support
------------------------

Autopush is capable of routing messages over Google Cloud Messaging/Firebase
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

.. _`docker`: https://www.docker.com/
.. _`docker-compose`: https://docs.docker.com/compose/
.. _`GCM`: http://developer.android.com/google/gcm/index.html
.. _`FCM`: https://firebase.google.com/docs/cloud-messaging/
.. _`on the wiki`: https://github.com/mozilla-services/autopush/wiki/Bridging-Via-GCM
