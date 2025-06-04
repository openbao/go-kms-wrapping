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

	export BAO_HSM_KEY_LABEL=$AES_KEY_LABEL
	# Without explicitly setting mechanism, should default to AES-GCM:
	go clean -testcache && go test -v -run '^TestWrapper$'
	# With explicitly set mechanism:
	export BAO_HSM_MECHANISM=CKM_AES_GCM
	go clean -testcache && go test -v -run '^TestWrapper$'
	unset BAO_HSM_MECHANISM

	export BAO_HSM_KEY_LABEL=$RSA_KEY_LABEL
	# Without explicitly setting mechanism, should default to RSA-OAEP:
	go clean -testcache && go test -v -run '^TestWrapper$' -run '^TestExternalKey$'
	# With explicitly set mechanism:
	export BAO_HSM_MECHANISM=CKM_RSA_PKCS_OAEP
	go clean -testcache && go test -v -run '^TestWrapper$' -run '^TestExternalKey$'
	unset BAO_HSM_MECHANISM

	export BAO_HSM_KEY_LABEL=$ECDSA_KEY_LABEL
	# Mechanism is not relevant for ExternalKey-only tests:
	go clean -testcache && go test -v -run '^TestExternalKey$'

	# Finally, check that only using the slot ID with no token label works:
	unset BAO_HSM_TOKEN_LABEL
	export BAO_HSM_SLOT=$(softhsm2-util --show-slots | grep '^Slot [0-9]*$' | awk '{print $2 }' | sort -n | tail -n 1)
	# We'll use RSA as it has the most "coverage":
	export BAO_HSM_KEY_LABEL=$RSA_KEY_LABEL
	go clean -testcache && go test -v -run '^TestWrapper$' -run '^TestExternalKey$'
EOF
