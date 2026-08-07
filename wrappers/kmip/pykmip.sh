#!/bin/bash

set -o xtrace

(
	echo "starting server..."
	~/.local/bin/pykmip-server --config_path=/go-kms-wrapping/wrappers/kmip/pykmip-server.conf
	echo "stopped server..."
) &
pid=$!

sleep 10

okms --config /go-kms-wrapping/wrappers/kmip/okms.yml kmip create symmetric --alg AES --size 256 --usage encrypt,decrypt --name bao_seal_key

sleep 10

echo "killing server..."
kill "$pid"
