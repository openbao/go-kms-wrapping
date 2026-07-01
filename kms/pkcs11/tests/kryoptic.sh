#!/usr/bin/env sh
set -e

export PKCS11_LIBRARY="${KRYOPTIC_LIBRARY}"

KRYOPTIC_CONF="$(mktemp -d)/kryoptic.conf"
export KRYOPTIC_CONF

cat > "${KRYOPTIC_CONF}" <<-EOF
  [[slots]]
  slot = 0
  dbtype = "sqlite"
  dbargs = "$(mktemp -d)/db.sql"
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
