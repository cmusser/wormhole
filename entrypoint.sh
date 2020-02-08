#!/bin/bash

function check_wormhole_args() {
    if [ -z "${LISTEN_ADDR+x}" ] ; then
        echo "listen socket address (\$LISTEN_ADDR) not set."
        exit 1
    fi

    if [ -z "${CONNECT_ADDR+x}" ] ; then
        echo "connect socket address (\$CONNECT_ADDR) not set"
        exit 1
    fi
}

if [ "$1" = "client-proxy" ] ; then
    check_wormhole_args
    RUN_WORMHOLE=true
elif [ "$1" = "server-proxy" ] ; then
    check_wormhole_args
    RUN_WORMHOLE=true
    SERVER="-S"
elif [ "$1" = "keygen" ] ; then
    wormhole-keygen
elif [ "$1" = "help" ] ; then
    echo 'specify "wormhole-client", "wormhole-server", "wormhole-keygen" or arbitrary command.'
    echo
    echo 'For any of the wormhole-* commands, mount a directory where a secret key named "key.yaml"'
    echo 'will be read from or written to.'
    echo
    echo 'For client or server, the following environment variables can be set:'
    echo 'LISTEN_ADDR  : <host|ip>:port (socket address to listen on)'
    echo 'CONNECT_ADDR : <host|ip>:port (socket address to connect to)'
    echo 'LOG_LEVEL    : tracing level (env_logger syntax, e.g. wormhole=info)'
    echo
    echo 'Note that RUST_LOG has a default appropriate for production user. The *_ADDR'
    echo 'vars have defaults, but they will almost always need to be given application'
    echo 'specific values.'
else
    echo command was $1
    exec "$@"
fi

if [ ! -z "${RUN_WORMHOLE+x}" ] ; then
    RUST_LOG=${LOG_LEVEL:-wormhole=warn} wormhole ${SERVER} -c ${LISTEN_ADDR} -s ${CONNECT_ADDR} -k /etc/wormhole/key.yaml
fi
