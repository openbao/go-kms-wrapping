# PKCS#11 KMS Provider

This is the PKCS#11 implementation of the
[KMS interface](https://github.com/openbao/go-kms-wrapping/tree/main/kms).

## Tests

Tests in this module run against [SoftHSM](https://github.com/softhsm/SoftHSMv2)
and [Kryoptic](https://github.com/latchset/kryoptic).

To enable:

- For SoftHSM, set the `SOFTHSM_PATH` environment variable to point at SoftHSM's
  dynamic library, e.g., `SOFTHSM_PATH=/usr/lib/libsofthsm2.so`.

- For Kryoptic, set the `KRYOPTIC_PATH` environment variable to point at
  Kryoptic's dynamic library, e.g., `KRYOPTIC_PATH=/usr/lib/libkryoptic_pkcs11.so`.

Ephemeral key material and configuration is created for each test run inside of
temporary directories, so no further setup is necessary.
