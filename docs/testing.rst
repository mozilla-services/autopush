.. _testing:

=======
Testing
=======

Running Tests
=============

If you plan on doing development and testing, you will need to install some additional packages.

.. code-block:: bash

    $ bin/pip install -r test-requirements.txt

Once the Makefile has been run, you can run ``make test`` to run the test suite.

.. note::

    Failures may occur if a ``.boto`` file exists in your home directory. This
    file should be moved elsewhere before running the tests.

``make test`` runs the ``tox`` program which can be difficult to break for debugging purposes.  The following bash script has been useful for running tests outside of tox:

.. code-block:: bash

     #! /bin/bash
     mv autopush/tests/test_integration.py{,.hold}
     mv autopush/tests/test_logging.py{,.hold}
     bin/nosetests -sv autopush
     mv autopush/tests/test_integration.py{.hold,}
     mv autopush/tests/test_logging.py{.hold,}

This script will cause the integration and logging tests to not run.
