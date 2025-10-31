# PKCS#11 KMS Provider

This is the PKCS#11 implementation of the
[KMS interface](https://github.com/openbao/go-kms-wrapping/tree/main/kms).

## SoftHSM Tests

Tests in this module use SoftHSM to test against a "real enough" PKCS#11
library. SoftHSM tests generate the required ephemeral key material on the fly
and store it inside of temp directories that are removed on test completion.
They run quickly and are easy to set up for local testing on Linux or macOS.

1. Ensure SoftHSM v2 is installed. This includes the PKCS#11 dynamic library
   `libsofthsm2.so` and the `softhsm2-util` tool, which must be in `$PATH`.

2. To enable SoftHSM tests, set the `SOFTHSM_TESTS=1` environment
   variable. Additionally, set the `SOFTHSM_LIBRARY_PATH`
   environment variable to point at the dynamic library, e.g., via
   `SOFTHSM_LIBRARY_PATH=/usr/lib/softhsm/libsofthsm2.so`

3. `go test` away.

