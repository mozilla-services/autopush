#!/bin/sh

if [ "${USE_JEMALLOC:-false}" = "true" ]; then
    export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libjemalloc.so.1"
fi

exec "$@"
