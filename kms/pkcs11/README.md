# PKCS#11 KMS Provider

This is the PKCS#11 implementation of the
[KMS interface](https://github.com/openbao/go-kms-wrapping/tree/main/kms).

## Tests

Tests in this module are set up to run against a given PKCS#11 library path,
token label and PIN value, set via environment variables:

- `PKCS11_LIBRARY` - Full path to the PKCS#11 library to test against.
- `PKCS11_TOKEN` - Label of the token to test against.
- `PKCS11_PIN` - User PIN for the token to test against.

If any of the above environment variables are unset, tests in this module are
skipped.

Additionally, there are scripts available in [`tests/`](./tests) that
automatically prepare testing environments for well-known PKCS#11 libraries.
These wrap any command and can be used to launch a shell, debugger, or `go test`
directly:

```shell-session
$ SOFTHSM2_LIBRARY=/usr/lib/softhsm/libsofthsm2.so \
  ./tests/softhsm2.sh go test -v ./...

$ KRYOPTIC_LIBRARY=/usr/lib/libkryoptic_pkcs11.so \
  ./tests/kryoptic.sh go test -v ./...
```
