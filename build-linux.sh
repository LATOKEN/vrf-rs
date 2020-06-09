#!/bin/bash

mkdir -p lib/linux-x64
cargo build --release
cp target/release/libvrf.so lib/linux-x64/
