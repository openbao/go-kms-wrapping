# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

FROM openbao/openbao:latest

COPY <<-EOF /key-setup.sh
  set -e
  bao login token=root
  bao secrets enable transit
  bao write -f transit/keys/example
EOF

ENTRYPOINT ["sh", "/key-setup.sh"]
