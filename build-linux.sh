#!/bin/bash

docker build -t vrf-rs .
docker run --rm -v "$(pwd)/lib/linux-x64":/opt/dist vrf-rs