#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset

cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/machroot machroot
vsn=$(cat Cargo.toml | grep version | awk '{ print $3 }' | sed 's/"//g')
tar cf machroot-$vsn-x86_64-unknown-linux-musl.tar machroot
gzip machroot-$vsn-x86_64-unknown-linux-musl.tar
