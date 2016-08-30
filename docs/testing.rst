.. _testing:

=======
Testing
=======

Running Tests
=============

If you plan on doing development and testing, you will need to install some
additional packages.

.. code-block:: bash

    $ bin/pip install -r test-requirements.txt

Once the Makefile has been run, you can run ``make test`` to run the test suite.

.. note::

    Failures may occur if a ``.boto`` file exists in your home directory. This
    file should be moved elsewhere before running the tests.

Disabling Integration Tests
---------------------------

``make test`` runs the ``tox`` program which can be difficult to break for
debugging purposes.  The following bash script has been useful for running
tests outside of tox:

.. code-block:: bash

     #! /bin/bash
     mv autopush/tests/test_integration.py{,.hold}
     mv autopush/tests/test_logging.py{,.hold}
     bin/nosetests -sv autopush
     mv autopush/tests/test_integration.py{.hold,}
     mv autopush/tests/test_logging.py{.hold,}

This script will cause the integration and logging tests to not run.

.. _test-with-firefox:

Firefox Testing
===============

To test a locally running Autopush with Firefox, you will need to edit
several config variables in Firefox.

1. Open a New Tab.
2. Go to ``about:config`` in the Location bar and hit Enter, accept the disclaimer
   if it's shown.
3. Search for ``dom.push.serverURL``, make a note of the existing value (you can
   right-click the preference and choose ``Reset`` to restore the default).
4. Double click the entry and change it to ``ws://localhost:8080/``.
5. Right click in the page and choose ``New -> Boolean``, name it
   ``dom.push.testing.allowInsecureServerURL`` and set it to ``true``.

You should then restart Firefox to begin using your local Autopush.

Debugging
---------

On Android, you can set ``dom.push.debug`` to enable debug logging of Push
via ``adb logcat``.

For desktop use, you can set ``dom.push.loglevel`` to ``"debug"``. This will
log all push messagesto the Browser Console (Tools > Web Developer > Browser
Console).
