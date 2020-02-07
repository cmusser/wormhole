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
in a second. This example uses one host (localhost).

1. client proxy

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -c 127.0.0.1:8082 -s 127.0.0.1:8081

2. server gateway

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -S

3. server

        nc -4 -kl localhost 8080

4. client

        nc localhost 8082

As seen from the above examples, the `RUST_LOG` environment variable can be used to
specify the amount of diagnostic information printed.

### Protect Redis sessions

This is a more real-world application: accessing a Redis server. Because Redis is
a "real" server that can handle simultaneous connections, you repeat step 4 below
to see `wormhole` multiplexing connections from multiple Redis clients. This 
example features three hosts: a gateway, a host running Redis and a client machine. 

1. client proxy (on a gateway host)

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -c 0.0.0.0:6379 -s redis:26379

2. server gateway (on the Redis server host)

        RUST_LOG="wormhole=trace" cargo run --bin wormhole -- -S -c 0.0.0.0 26379 -s 127.0.0.1:6379

3. Redis server (on the Redis server host)

        sudo docker run --network=host -it --rm -p 6379:6379 --name redis redis

4. Redis CLI (on your local host)

       redis-cli -h gateway

## Docker Container

Use cases similar to the above can also be accomplished with the Docker container,
which makes it easy to run a proxy or bundle it with an application, i.e. with
Docker Compose.

The container has built-in commands for running as a client or server gateway,
generating a key with the `wormhole-keygen` utility and running an arbitrary
command in the container.

The following table shows the various commands and the configuration environment
variables available:

|Command|Environment Variables|Notes|
|client-proxy|LISTEN_ADDR, CONNECT_ADDR, LOG_LEVEL|create a client proxy, which encrypts data received from connections it accepts from clients, and decrypts data received from connections it makes to the server proxy.|
|server-proxy|LISTEN_ADDR, CONNECT_ADDR, LOG_LEVEL|create a server proxy, which decrypts data received from connections it accepts from client proxies, and encrypts data received froo connections it makes to the server.|
|keygen|none|Create a secret key named `key.yaml` for use by both peers. This key will be written to the directory mounted into the container.|
|help|none|Show usage information|
|anything else|none|Only `wormhole` and `wormhole-keygen` are in the container, but you can run them with all possible arguments|

For the `client-proxy` and `server-proxy`, specify LISTEN_ADDR and CONNECT_ADDR as appropriate for your application. The defaults for these
are for testing and are unlikely to match what you need. The LOG_LEVEL variable is in `env_logger`/`tracing` syntax.

Also, for `client-proxy`, and `server-proxy`, mount a file inside the container at `/etc/wormhole/key.yaml. For `keygen` mount the
directory where you want the new key to be generated at `/etc/wormhole`.

## Implementation Details

`wormhole` is written in Rust. It uses the following features.

* The `async/.await` language feature, introduced in Rust 1.39
* `tokio` 0.2 (the initial version designed to work with `async/.await`)
* `futures` 0.3
* `tracing`, for diagnostics
* `sodiumoxide`, the libsodium wrapper
* `structopt`, for CLI argument processing

## Proxy Design Notes

There are a number of ways to implement a streaming proxy. Each has
various tradeoffs involving efficiency, responsiveness and security.

### Optimized for Interactivity (Current Implementation)

`wormhole` implements simple scheme wherein every plaintext packet
received is padded out to a fixed length, encrypted and sent to the peer
proxy. The peer proxy, in turn, is responsible for reading complete
messages (it can, because the message size is fixed and hence known
in advance), decrypting them and forwarding them on. One advantage of
this is good interactivity: data is sent as soon as it is received,
so that interactive sessions are responsive and do not lag while a
buffer is being filled. Padding ensures that messages are always the
same size, which makes it harder to infer anything about the traffic
based on the size alone. On the minus side, a fixed message size lead
to some inefficiency. If the data is sent in increments significantly
smaller than the encrypted message size, most of the bandwidth will be
used by the padding. If the traffic is streaming a large amount of data
it may result in little padding, but a significant amount of CPU might
be expended encrypting many small ciphertexts.  Finally, the message
size can be adjusted, but if the traffic's send sizes and burstiness are
unpredicable, choosing an optimal value is difficult.

### An Enhancement to the Above, for Bandwidth Efficiency

For greater efficiency in cases where interactivity is not as important,
the encrypting side could buffer data before encrypting and sending. This
would remove the bandwidth inefficiency introduced by padding. Only
the final message would likely be padded: the proxy would know to
send whatever it had accumulated when the "edge system" closes the
connection. This technique is essentially an extension of the one
described above and could be enabled with a configuration parameter.

### Length Header Instead of Padding

A somewhat different scheme that allows good interactive responsiveness
would be to encrypt and send data as it arrives, but instead of padding
it to a fixed length, prefix every send with a length. The decrypting
side would begin every session by reading the length header for the
first message, using that as the amount to read before decrypting
and sending. After forwarding, the process repeats: it reads the
next length header, then begins the process of accumulating the next
(probably differently sized) message.  Allowing arbitrary message
sizes provides good interactivity. If the amount of data transferred is
large in terms of size or number of segments, it becomes inefficient
in terms of encryption cost, as in the first scheme. It does have the
disadvantage of leaking "metadata" about the traffic (the message sizes)
in the clear. This could be used to make inferences about the nature of
the traffic. Malicious actors could also alter the traffic in transit,
altering the size values to cause decryption to fail or the process to
mismanage its buffers (although a Rust program is likely to simply crash,
rather than fall victim to a buffer overflow.)

## Acknowledgements

`wormhole` was initially based on examples in the
[Tokio](https://github.com/tokio-rs/tokio) repository's 0.2 alpha branch,
although its structure no longer resembles that program. A technique forr
ensuring proper session cleanup was found in the earlier 0.1 branch examples.
Initial versions implemented the `AsyncRead` trait on readers and used the
`copy()` method to move data between proxy processes. This was found to be
flawed, but valuable experience was gained by building it. While doing so, I
got helpful advice from `Nemo157` and `sfackler` on the Rust [users discussion
site](https://users.rust-lang.org). Frank Denis (libsodium's maintainer)
suggested ways for properly handling an encrypted stream, which I expanded in
to the Proxy Design Notes above.
