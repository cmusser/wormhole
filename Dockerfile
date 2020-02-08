FROM rust:1.41.0 AS build
MAINTAINER Chuck Musser <cmusser@sonic.net>

# Multi-stage Rust build and image creation technique courtesy of:
# https://alexbrand.dev/post/how-to-package-rust-applications-into-minimal-docker-containers/

# Creating an empty project with only the Cargo config and lockfile,
# and then building it results the project's dependencies being built.
# This leverages the Docker build cache. If the Cargo.toml or Cargo.lock
# files haven't changed, the build is skipped and the still current
# dependencies are used as-is.
WORKDIR /usr/src
RUN USER=root cargo new --bin wormhole
WORKDIR /usr/src/wormhole
COPY Cargo.toml Cargo.lock ./
RUN touch src/lib.rs
RUN echo "fn main() {println!(\"dummy wormhole binary\")}" > src/wormhole.rs
RUN echo "fn main() {println!(\"dummy wormhole-keygen binary\")}" > src/wormhole-keygen.rs
RUN cargo build --release

# Copy the source and build the application. The install command builds
# if needed. Not sure why --path . puts things in /usr/local/bin/
COPY src ./src
RUN cargo install --path .

# Copy the statically-linked binary into a scratch container.
FROM debian:buster-slim
COPY --from=build /usr/local/cargo/bin/wormhole /usr/bin
COPY --from=build /usr/local/cargo/bin/wormhole-keygen /usr/bin
COPY entrypoint.sh ./
USER 1000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["help"]
