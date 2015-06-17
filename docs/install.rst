.. _install:

==========
Installing
==========

Using PyPy
==========

You will first need to get pypy as appropriate for your system and put it's
uncompressed folder in the autopush directory as ``pypy``.

PyPy downloads can be found here: http://pypy.org/download.html#default-with-a-jit-compiler
autopush requires PyPy >= 2.6.

Once you have downloaded, decompressed, and renamed this to ``pypy``, you can
run the Makefile with ``make``, which will setup the application.

Python 2.7.7+ w/virtualenv
==========================

You will need ``virtualenv`` installed, then create a virtualenv named ``pypy``
and symlink ``pypy/bin/python`` -> ``pypy/bin/pypy``:

.. code-block:: bash

    $ virutalenv pypy
    $ cd pypy/bin
    $ ln -s python pypy
    $ cd ../..

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
