# We use Fedora Rawhide at this moment as it packages Kryoptic >= v1.5.0, which
# has bug fixes related to AES-GCM that are not present in earlier versions.
# Once more generally available, a different base image can be picked.
FROM registry.fedoraproject.org/fedora-minimal:rawhide

RUN dnf -y update && \
	dnf -y install --nodocs --setopt=install_weak_deps=False golang softhsm kryoptic

ENV SOFTHSM_PATH=/usr/lib64/pkcs11/libsofthsm2.so
ENV KRYOPTIC_PATH=/usr/lib64/pkcs11/libkryoptic_pkcs11.so

WORKDIR /go-kms-wrapping
COPY go.mod go.sum ./
WORKDIR /go-kms-wrapping/kms/pkcs11
COPY kms/pkcs11/go.mod kms/pkcs11/go.sum ./
RUN go mod download
COPY . /go-kms-wrapping

ARG TESTFLAGS=-v
RUN CGO_ENABLED=1 go test ${TESTFLAGS} ./...
