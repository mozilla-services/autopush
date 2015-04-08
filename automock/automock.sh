#!/usr/bin/env bash

set -e
PATH="`pwd`/pypy/bin:$PATH"

moto_server dynamodb2 -p 5000 &
autonode
