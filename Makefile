SHELL := /bin/sh
APPNAME = autopush
DEPS =
HERE = $(shell pwd)
PTYPE=python
BIN = $(HERE)/bin
VIRTUALENV = virtualenv
TESTS = $(APPNAME)/tests
PYTHON = $(BIN)/$(PTYPE)
INSTALL = $(BIN)/pip install
PATH := $(BIN):$(PATH)

BUILD_DIRS = bin build deps include lib lib64 lib_pypy lib-python\
	src site-packages .tox .eggs .coverage


.PHONY: all build test coverage lint clean clean-env

all:	build

$(BIN)/pip: $(PYTHON)
	curl -O https://bootstrap.pypa.io/get-pip.py
	$(PYTHON) get-pip.py
	rm get-pip.py

$(BIN)/tox: $(BIN)/pip
	$(INSTALL) tox

$(BIN)/flake8: $(BIN)/pip
	$(INSTALL) flake8

$(BIN)/paster: lib $(BIN)/pip
	$(INSTALL) -r requirements.txt
	$(PYTHON) setup.py develop

clean-env:
	rm -rf *.egg-info
	rm -rf $(BUILD_DIRS)

clean:	clean-env

build: $(BIN)/pip
	$(INSTALL) -r requirements.txt
	$(PYTHON) setup.py develop

test: $(BIN)/tox
	$(BIN)/tox

coverage: $(BIN)/tox
	$(BIN)/tox -- --with-coverage --cover-package=autopush

lint: $(BIN)/flake8
	$(BIN)/flake8 autopush
