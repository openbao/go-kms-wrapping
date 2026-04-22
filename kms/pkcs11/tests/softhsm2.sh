#!/usr/bin/env sh
set -e

export PKCS11_LIBRARY="${SOFTHSM2_LIBRARY}"

SOFTHSM2_CONF="$(mktemp -d)/softhsm2.conf"
export SOFTHSM2_CONF

cat > "${SOFTHSM2_CONF}" <<-EOF
  log.level = INFO
  directories.tokendir = $(mktemp -d)
EOF

export PKCS11_PIN=abcd-1234
export PKCS11_TOKEN=go-kms-wrapping

softhsm2-util \
  --init-token --slot 0 \
  --module "${PKCS11_LIBRARY}" \
  --label  "${PKCS11_TOKEN}" \
  --so-pin "${PKCS11_PIN}" \
  --pin    "${PKCS11_PIN}"

exec "$@"
