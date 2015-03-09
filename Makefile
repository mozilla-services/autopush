APPNAME = autopush
DEPS =
HERE = $(shell pwd)
BIN = $(HERE)/bin
VIRTUALENV = virtualenv
NOSE = bin/nosetests -s --with-xunit
TESTS = $(APPNAME)/tests
PYTHON = $(HERE)/bin/pypy
INSTALL = $(HERE)/bin/pip install

BUILD_DIRS = bin build deps include lib lib64 lib_pypy lib-python


.PHONY: all build test clean clean-env

all:	build

$(BIN)/pypy:
	wget https://bitbucket.org/pypy/pypy/downloads/pypy-2.5.0-linux64.tar.bz2
	tar xjvf pypy-2.5.0-linux64.tar.bz2
	rm pypy-2.5.0-linux64/README.rst
	mv pypy-2.5.0-linux64/* .
	rm -rf pypy-2.5.0-linux64*

$(BIN)/pip: $(BIN)/pypy
	wget https://bootstrap.pypa.io/get-pip.py
	$(PYTHON) get-pip.py
	rm get-pip.py

$(BIN)/nosetests:
	$(INSTALL) nose
	$(INSTALL) coverage

$(BIN)/paster: lib $(BIN)/pip
	$(INSTALL) -r requirements.txt
	$(PYTHON) setup.py develop

clean-env:
	rm -rf $(BUILD_DIRS)

clean:	clean-env

build: $(BIN)/pip
	$(INSTALL) -r requirements.txt
	$(PYTHON) setup.py develop

test: $(BIN)/nosetests
	$(NOSE) --with-coverage --cover-package=ofcode --cover-erase \
	--cover-inclusive $(APPNAME)
