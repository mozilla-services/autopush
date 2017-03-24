========
autopush
========

.. image:: https://travis-ci.org/mozilla-services/autopush.svg?branch=master
    :target: https://travis-ci.org/mozilla-services/autopush

.. image:: https://codecov.io/github/mozilla-services/autopush/coverage.svg
  :target: https://codecov.io/github/mozilla-services/autopush

Mozilla Push server and Push Endpoint utilizing PyPy, twisted, and DynamoDB.

This is the third generation of Push server built in Mozilla Services, first
to handle Push for FirefoxOS clients, then extended for push notifications for
Firefox (via the `W3C Push spec <http://w3c.github.io/push-api/index.html>`_.)

For how to read and respond to **autopush error codes**, see
:ref:`Errors <errors>`.

For an overview of the Mozilla Push Service and where autopush fits in, see
the `Mozilla Push Service architecture diagram`_. This push service uses
websockets to talk to Firefox, with a Push endpoint that implements the
:term:`WebPush` standard for its :ref:`http` API.

Autopush APIs
=============

For developers writing mobile applications in Mozilla, or web developers using
Push on the web with Firefox.

.. toctree::
    :maxdepth: 2

    http

.. _running-autopush:

Running Autopush
================

If you just want to run autopush, for testing Push locally with
Firefox, or to deploy autopush to a production environment for Firefox.

.. toctree::
   :maxdepth: 2

   architecture
   running

.. _developing:

Developing Autopush
===================

For developers wishing to work with the latest autopush source code, it's
recommended that you first familiarize yourself with
:ref:`running Autopush <running-autopush>` before proceeding.

.. toctree::
   :maxdepth: 2

   install
   testing
   releasing
   style

Source Code
===========

All source code is available on `github under autopush
<https://github.com/mozilla-services/autopush>`_.

:ref:`api`

.. toctree::
    :hidden:

    api

Changelog
=========

.. toctree::
   :maxdepth: 2

   Changelog <https://github.com/mozilla-services/autopush/blob/master/CHANGELOG.md>


Bugs/Support
============

Bugs should be reported on the `autopush github issue tracker
<https://github.com/mozilla-services/autopush/issues>`_.

The developers of ``autopush`` can frequently be found on the Mozilla IRC
network (irc.mozilla.org) in the `\#push`_ channel.

autopush Endpoints
==================

autopush is automatically deployed from master to a dev environment for testing,
a stage environment for tagged releases, and the production environment used by
Firefox/FirefoxOS.

dev
---

* Websocket: wss://autopush.dev.mozaws.net/
* Endpoint: https://updates-autopush.dev.mozaws.net/

stage
-----

* Websocket: wss://autopush.stage.mozaws.net/
* Endpoint: https://updates-autopush.stage.mozaws.net/

production
----------

* Websocket: wss://push.services.mozilla.com/
* Endpoint: https://updates.push.services.mozilla.com/

Reference
=========

* :ref:`genindex`
* :ref:`modindex`
* :ref:`glossary`

.. toctree::
   :hidden:

   glossary

License
=======

``autopush`` is offered under the Mozilla Public License 2.0.

.. _\#push: irc://irc.mozilla.org/push
.. _Mozilla Push Service architecture diagram: http://mozilla-push-service.readthedocs.io/en/latest/#architecture
