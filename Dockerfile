FROM rust:stretch
WORKDIR /vrf-rs
COPY src src
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
RUN OPENSSL_STATIC=1 cargo build --release
ENTRYPOINT ["bash", "-c", "cp /vrf-rs/target/release/libvrf.so /opt/dist"]