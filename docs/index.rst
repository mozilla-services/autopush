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

Reference Docs
==============

.. toctree::
   :maxdepth: 1

   install
   testing
   running
   architecture
   api
   Changelog <changelog>
   http

Source Code
===========

All source code is available on `github under autopush
<https://github.com/mozilla-services/autopush>`_.

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

* Websocket: wss://autopush-dev.stage.mozaws.net/
* Endpoint: https://updates-autopush-dev.stage.mozaws.net/

stage
-----

* Websocket: wss://autopush.stage.mozaws.net/
* Endpoint: https://updates-autopush.stage.mozaws.net/

production
----------

* Websocket: wss://push.services.mozilla.com/
* Endpoint: https://updates.push.services.mozilla.com/

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`glossary`

.. toctree::
   :hidden:

   glossary

License
=======

``autopush`` is offered under the Apache License 2.0.

.. _\#push: irc://irc.mozilla.org/push
