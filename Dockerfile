FROM rust:stretch
WORKDIR /vrf-rs
COPY src src
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
RUN OPENSSL_STATIC=yes OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/ OPENSSL_INCLUDE_DIR=/usr/include cargo build --release
ENTRYPOINT ["bash", "-c", "cp /vrf-rs/target/release/libvrf.so /opt/dist"]
