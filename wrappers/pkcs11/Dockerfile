# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv

FROM docker.io/golang:latest

# Install required packages:
RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends golang-go softhsm2 opensc

ENV SO_PIN=1234
ENV BAO_HSM_LIB=/usr/lib/softhsm/libsofthsm2.so

ENV BAO_HSM_PIN=4321
ENV BAO_HSM_TOKEN_LABEL=openbao/go-kms-wrapping

# We'll create an AES, RSA and ECDSA key each.
ENV AES_KEY_LABEL=bao-aes
ENV RSA_KEY_LABEL=bao-rsa
ENV ECDSA_KEY_LABEL=bao-ecdsa

RUN <<EOF
  set -e

	# Initialize a slot, --slot 0 will allocate some random slot, not 0!
	softhsm2-util --init-token --slot 0 --label "$BAO_HSM_TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$BAO_HSM_PIN"

	# Create our keys:
	pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$BAO_HSM_PIN" \
		--keygen --key-type aes:32 --label "$AES_KEY_LABEL"
	pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$BAO_HSM_PIN" \
		--keypairgen --key-type rsa:4096 --label "$RSA_KEY_LABEL"
	pkcs11-tool --module "$BAO_HSM_LIB" --token-label "$BAO_HSM_TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$BAO_HSM_PIN" \
		--keypairgen --key-type ec:prime256v1 --label "$ECDSA_KEY_LABEL"
EOF

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum .

WORKDIR /go-kms-wrapping/wrappers/pkcs11
COPY ./wrappers/pkcs11/go.mod ./wrappers/pkcs11/go.sum .

RUN go mod download

COPY . /go-kms-wrapping

ENV KMS_ACC_TESTS=true

# SoftHSM only supports SHA1.
ENV BAO_HSM_RSA_OAEP_HASH=SHA1

RUN <<EOF
  set -e

	# Tests that don't require a key:
	go clean -testcache && go test -v -run '^Test(Module|Pool|Client)$'

	# AES
	export BAO_HSM_KEY_LABEL=$AES_KEY_LABEL
	go clean -testcache && go test -run '^TestWrapper$'

	# RSA
	export BAO_HSM_KEY_LABEL=$RSA_KEY_LABEL
	go clean -testcache && go test -run '^Test(Wrapper|ExternalKey)$'

	# ECDSA
	export BAO_HSM_KEY_LABEL=$ECDSA_KEY_LABEL
	go clean -testcache && go test -run '^TestExternalKey$'
EOF
