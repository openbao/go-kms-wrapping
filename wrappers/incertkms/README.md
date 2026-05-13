# incertkms wrapper

Provides integration with [INCERT KMS](https://kms-uat.incert.lu/), a hosted Key Management Service developed by INCERT. The wrapper uses the
[`kms-sdk-go`](https://github.com/incert-kms/kms-sdk-go) client to talk to the KMS REST API.

Sealing is performed with an AES-256 key (algorithm `AES_GCM`) that lives on the KMS side. The wrapper never sees the key material: encryption and decryption of the seal payload happen entirely on the KMS.

## Settings

| Field          | Required | Default                            | Description                                                                                                                       |
| -------------- | -------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `kms_url`      | yes      | `https://kms-uat.incert.lu/kms`    | Base URL of the KMS instance. The wrapper appends `/api` when calling the REST API.                                               |
| `kms_username` | yes      |                                    | Username of the KMS account.                                                        |
| `kms_password` | yes      |                                    | Password of the KMS account.                                                        |
| `kms_vslot`    | no       |                                    | UUID of the vslot that stores the seal key. Required when the account has more than one vslot; auto-selected when only one exists. |
| `kms_key`      | no       |                                    | UUID of an existing key to use for sealing. Must be an AES key.                                                                   |
| `kms_key_name` | no       | `openbao-seal-key`                 | Name used to look up an existing key in the vslot, and to label a freshly created key when neither `kms_key` nor a matching name is found. |

### Key resolution

On startup, the wrapper picks the sealing key in this order:

1. If `kms_key` is set, the key is loaded by ID. The KMS must contain a key with this UUID and it must be readable by the configured user.
2. Otherwise, the wrapper looks for a key in `kms_vslot` whose name matches `kms_key_name` (default `openbao-seal-key`). The most recently created match is used. Only AES keys are accepted.
3. If neither of the above produces a key, a new AES-256 key is created on first `Encrypt` and named `kms_key_name`.

### Key rotation

Rotating a key in KMS creates a new key that shares the previous key's attributes and name but has a new UUID. Because the wrapper resolves keys by name and picks the most recently created match, it starts using the rotated key on the next startup with no configuration change.

This automatic behaviour only applies when the wrapper is configured by name (via `kms_key_name` or its default). If `kms_key` is set, the wrapper is pinned to that exact UUID; to switch keys in that mode, update `kms_key` to the new UUID. The new key does not need to be related to the previous one.

## Example openbao.hcl

```hcl
seal "incertkms" {
  kms_url      = "http://localhost:3000"
  kms_username = "kms-user"
  kms_password = "pa55w0rd"
  kms_vslot    = "a73b7303-ce75-4666-8a3d-e9fb269424fb"
  kms_key      = "bd5d7c4b-8ed3-4390-bcee-f37446bb420f"
  kms_key_name = "openbao-seal-key"
}
```

## Testing

```sh
go test ./...
```

