# OpenStack Barbican wrapper

This wrapper retrieves a pre-provisioned OpenStack Barbican symmetric secret and
uses the secret payload as a local AES-GCM wrapping key.

## Configuration

The wrapper supports these configuration map keys:

| Key | Required | Description |
| --- | --- | --- |
| `secret_ref` | yes | Barbican secret UUID or full secret URL. |
| `endpoint` | no | HTTPS Barbican endpoint override. |
| `region` | no | OpenStack region override. |

Authentication uses `OS_CLOUD` and `clouds.yaml` when `OS_CLOUD` is set.
Otherwise, authentication uses the standard OpenStack `OS_*` environment
variables supported by Gophercloud.

```go
wrapper := openstackbarbican.NewWrapper()
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
	"secret_ref": "00000000-0000-0000-0000-000000000000",
	"region":     "DFW",
}))
```

## Secret Requirements

The configured Barbican secret must have:

* Secret type `symmetric`
* Default content type `application/octet-stream`
* A 32-byte payload

The payload is fetched from Barbican and used directly as the AES-256-GCM key.
This is different from KMS integrations that keep key material non-exportable
and perform cryptographic operations remotely. Operators should treat Barbican
payload read access as wrapping-key access.

## Endpoint Security

The effective Barbican endpoint must use HTTPS. Plaintext `http://` endpoints
are rejected for explicit `endpoint` configuration and for endpoints discovered
from the OpenStack service catalog. This is required because Barbican payload
retrieval returns the raw wrapping key to the client.

## Acceptance Testing

The acceptance test uses a pre-existing Barbican secret. It does not create or
delete OpenStack resources.

Required environment:

* `VAULT_ACC` or `KMS_ACC_TESTS`
* `OS_CLOUD`, or standard OpenStack `OS_*` authentication variables
* `OPENSTACKBARBICAN_SECRET_REF`

Optional environment:

* `OPENSTACKBARBICAN_ENDPOINT`
* `OPENSTACKBARBICAN_REGION`

Example:

```sh
export VAULT_ACC=1
export OS_CLOUD=my-openstack-cloud
export OPENSTACKBARBICAN_SECRET_REF=00000000-0000-0000-0000-000000000000
go test ./...
```
