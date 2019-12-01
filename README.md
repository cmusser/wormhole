# Wormhole: an encrypted TCP application tunnel system

## Overview

`wormhole` provides encrypted transport between clients and servers
that don't provide encryption on their own.

A `wormhole` system consists of a pair of processes, one for accepting
client connections and one for connecting to the destination server.
When a client connects to the client proxy, it makes a connection
to the server proxy, which in turn contacts the server. Client
packets arriving at the client proxy are encrypted and forwarded
on to the server proxy, which decrypts them and forwards them
on to the server. The same thing happens in the reverse direction.

`wormhole` processes accept multiple connections in both "client proxy"
and "server proxy" mode, making it possible to service many clients and
also create meshes of proxies for redundancy or to minimize service
disruptions.

## Usage Examples

Use `wormhole-keygen` to create a file with a secret key for use by both
sides of the proxy:

        cargo run --bin wormhole-keygen

### Send lines with `nc(1)`

This is a basic demonstration. You can type in one terminal and see it echoed
in a second.

1. client proxy

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -c 127.0.0.1:8082 -s 127.0.0.1:8081

2. server gateway

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -S

3. server

        nc -4 -kl localhost 8080

4. client

        nc localhost 8082

### Protect Redis sessions

This is a more real-world application: accessing a Redis server. Because Redis is
a "real" server that can handle simultaneous connections, you repeat step 4 below
to see `wormhole` multiplexing connections from multiple Redis clients.

1. client proxy

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -c 127.0.0.1:9090 -s 127.0.0.1:8081

2. server gateway

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -S -s 127.0.0.1:6379

3. Redis server

        sudo docker run --network=host -it --rm -p 6379:6379 --name redis redis

4. Redis CLI

       sudo docker run --network=host -it --rm --name redis-cli redis redis-cli -p 9090

## Implementation Details

`wormhole` is written in Rust. It uses the following features. Some of these are
bleeding edge as of Winter 2019, but might not be worth mentioning after they
become __de rigeur__.

* The `async/.await`-aware version of Tokio (initially 0.2)
* `futures` 0.3
* `tracing`, for diagnostics
* `sodiumoxide`, the libsodium wrapper
* Structopt, for CLI argument processing

## Acknowledgements

`wormhole` is based on examples in the [Tokio](https://github.com/tokio-rs/tokio)
repo. The overall structure, which uses `async/.await` is from the example in the
0.2 branch. A technique for ensuring proper session cleanup was found in the 0.1
example. Tips on implementing the connection readers came from `Nemo157` and
`sfackler` on the Rust [users discussion site](https://users.rust-lang.org).
