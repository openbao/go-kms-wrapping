FROM docker.io/golang:latest

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends softhsm2

ENV CGO_ENABLED=1
ENV SOFTHSM_TESTS=1

WORKDIR /go-kms-wrapping
COPY ./go.mod ./go.sum ./

WORKDIR /go-kms-wrapping/kms/pkcs11
COPY ./kms/pkcs11/go.mod ./kms/pkcs11/go.sum ./

RUN go mod download
COPY . /go-kms-wrapping

ARG TESTFLAGS=-v
RUN go test ${TESTFLAGS} ./...
