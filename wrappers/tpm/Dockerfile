# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv

FROM docker.io/golang:latest

# docker build  --progress=plain   -f wrappers/tpm/Dockerfile .

# Install required packages:
RUN apt update && \
	DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends swtpm swtpm-tools

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./

WORKDIR /go-kms-wrapping/wrappers/tpm
COPY ./wrappers/tpm/go.mod ./wrappers/tpm/go.sum ./

RUN go mod download

COPY . /go-kms-wrapping

ENV TPM_ACC_TESTS=true

COPY <<EOF /go-kms-wrapping/wrappers/tpm/swtpm-setup.sh
set -e

mkdir /tmp/myvtpm

swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert 
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &

sleep 2

go test -v 
EOF

RUN chmod +x /go-kms-wrapping/wrappers/tpm/swtpm-setup.sh

RUN /go-kms-wrapping/wrappers/tpm/swtpm-setup.sh
 