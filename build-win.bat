set OPENSSL_STATIC=1
set RUSTFLAGS=-Ctarget-feature=+crt-static
cargo build --release
