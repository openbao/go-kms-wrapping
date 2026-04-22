# Fedora is one of the few distributions that packages Kryoptic,
# so use that as a base image to avoid building from source.
# Also see: https://repology.org/project/kryoptic/versions
FROM registry.fedoraproject.org/fedora-minimal

RUN dnf -y update && \
	dnf -y install --nodocs --setopt=install_weak_deps=False golang softhsm kryoptic

ENV SOFTHSM2_LIBRARY=/usr/lib64/pkcs11/libsofthsm2.so
ENV KRYOPTIC_LIBRARY=/usr/lib64/pkcs11/libkryoptic_pkcs11.so

WORKDIR /go-kms-wrapping
COPY go.mod go.sum ./
WORKDIR /go-kms-wrapping/kms/pkcs11
COPY kms/pkcs11/go.mod kms/pkcs11/go.sum ./
RUN go mod download
COPY . /go-kms-wrapping

ENV CGO_ENABLED=1
RUN <<-EOF
	./tests/softhsm2.sh go test -p 1 -v ./... || failed=1
	./tests/kryoptic.sh go test -p 1 -v ./... || failed=1
	test -z "$failed"
EOF
