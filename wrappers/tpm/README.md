# TPM Key Wrapping

Plugin provides the ability to use a `Trusted Platform Module (TPM)` to seal and unseal keys

You can use this to seal data upto `128 bytes` within a TPM object.

The sealed data can only get recovered on the same TPM it was sealed agains.

This library also supports sealing data and binding it to a certain passphrase or TPM PCRs values

For an example of standalone usage, see the example below.

### Environment Variable Override

You can override the configuration values provided in the file by using the following env-var overrides


| Option | Description |
|:------------|-------------|
| **`TPM_PATH`** | Path to the TPM device (default: `/dev/tpmrm0`) |
| **`TPM_PCRVALUES`** | Comma separated PCR banks to bind the key to.  See Policy Constrains section (default: ``) |
| **`TPM_USERAUTH`** | Password to bind the key to.  See Policy Constrains section (default: ``) |
| **`TPM_HIERARCHYAUTH`** | Password of the TPM hierarchy (default: `""`) |

### Configuration Variables

You can specify the same values in the config file variables:

| Option | Description |
|:------------|-------------|
| **`tpm_path`** | Path to the TPM device (default: `/dev/tpmrm0`) |
| **`tpm_pcrvalues`** | Comma separated PCR banks to bind the key to.  See Policy Constrains section (default: ``) |
| **`tpm_userauth`** | Password to bind the key to.  See Policy Constrains section (default: ``) |
| **`tpm_hierarchyauth`** | Password of the TPM hierarchy (default: `""`) |

for example,

```json
seal "tpm" {
  tpm_path = "/dev/tpmrm0"
  tpm_pcrvalues = "23:0000000000000000000000000000000000000000000000000000000000000000"
  tpm_userauth = "foo"
}
```

### TPM Policy Constraints

TPM wrapper support the following constraints set while sealing which must be fulfilled while unsealing

### UserAuth

The userauth constraints basically a passphrase which must be provided when sealing the data and the same passphrase for unsealing.

```bash
export TPM_USERAUTH=foo
```

or 

```
seal "tpm" {
  tpm_path = "/dev/tpmrm0"
  tpm_userauth=foo
} 
```

### PCR

For PCR binding, specify the PCR index and sha256 hex value to bind to.  

Each pcr bank must comma separated and formatted as `int(index):hex(sha256(pcr_value))`.

For example, to bind to pcrs 15, 23 which has the following values,

```bash
$ tpm2_pcrread sha256:15,23
 sha256:
	15: 0x0000000000000000000000000000000000000000000000000000000000000000
	23: 0xF5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

the string format for to specify would be the following.  Note the index value should be ascending and the `0x` from `tpm2_pcrread` format is omitted.

```bash
export TPM_PCRVALUES=15:0000000000000000000000000000000000000000000000000000000000000000,23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
```

or 

```
seal "tpm" {
  tpm_path = "/dev/tpmrm0"
  tpm_pcrvalues=15:0000000000000000000000000000000000000000000000000000000000000000,23:F5A5FD42D16A20302798EF6ED309979B43003D2320D9F0E8EA9831A92759FB4B
} 
```

#### Common Errors

- Invalid Password

```log
[WARN]  failed to unseal core: error="fetching stored unseal keys failed: failed to decrypt keys from storage: go-tpm-wrapping: error executing unseal: TPM_RC_AUTH_FAIL (session 1): the authorization HMAC check failed and DA counter incremented"
```

- Invalid Encrypted Key for TPM

Indicates the TPM based sealing key cannot be decrypted by the given TPM.

Likley the TPM that was used to encrypt the sealing key is not the same one currently being used.

```log
[WARN]  failed to unseal core: error="fetching stored unseal keys failed: failed to decrypt keys from storage: go-tpm-wrapping:  error executing Load: TPM_RC_INTEGRITY (parameter 1): integrity check failed"
```

- Invalid PCR

Likely indicates the PCR value used to seal the key does not match match what is in the config file or in the actual PCR bank:


The following indicates the PCR value provided to the wrapper does not match the existing value of the PCR banks

```log
[WARN]  failed to unseal core: error="fetching stored unseal keys failed: failed to decrypt keys from storage: go-tpm-wrapping: error executing PolicyPCR: TPM_RC_VALUE (parameter 1): value is out of range or is not correct for the context"
```

The following indicates the PCR values provided to the wrapper matches what the TPM values are but does _not_ match what the key was initially bound to

```log
[WARN]  failed to unseal core: error="fetching stored unseal keys failed: failed to decrypt keys from storage: go-tpm-wrapping: error executing unseal: TPM_RC_POLICY_FAIL (session 1): a policy check failed"
```

#### Standalone Example

For a standalone wrapping/unwrapping example with a softwareTPM:

```bash
rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5
```

- main.go:

```golang
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	tpmwrap "github.com/openbao/go-kms-wrapping/wrappers/tpm/v2"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	tpmPath       = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	pcrValues     = flag.String("pcrValues", "", "SHA256 PCR Values to seal against 16:abc,23:foo")
	userAuth      = flag.String("userAuth", "", "object Password")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	wrapper := tpmwrap.NewWrapper()

	configMap := map[string]string{
		"tpm_path":      *tpmPath,
		"tpm_pcrvalues": *pcrValues,
		"tpm_userauth":  *userAuth,
	}

	_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
		os.Exit(1)
	}

	jsonStr := protojson.Format(blobInfo)
	fmt.Printf("BlobInfo: %s\n", jsonStr)

	fmt.Printf("WrappingKey: %s\n", string(blobInfo.KeyInfo.WrappedKey))
	fmt.Printf("Encrypted: %s\n", base64.StdEncoding.EncodeToString(blobInfo.Ciphertext))

	plaintext, err := wrapper.Decrypt(ctx, blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decrypted: %s\n", string(plaintext))
}

```

The output renders the encoded key and the decrypted data

```bash
$ go run main.go --tpm-path="127.0.0.1:2321" --dataToEncrypt=foo

BlobInfo: {
  "ciphertext":  "BdNE9boW0a91verJDCdq1ecjn30c6FwYz/gqxbLUTQ==",
  "keyInfo":  {
    "wrappedKey":  "eyJwY3JzIjp7fSwidHBtS2V5IjoiLS0tLS1CRUdJTiBUU1MyIFBSSVZBVEUgS0VZLS0tLS1cbk1JSUJDQVlHWjRFRkNnRURvQU1CQWY4Q0JFQUFBQUVFVUFCT0FBZ0FDd0FBQUJJQUlPRzZ4amgvcVk5MlNZVlNcbnQrQTdhdW03VGhGeFUweFo3cTdBOU15THhEZm1BQkFBSUhWeTFBeFh1MEhFSCtuSWp1akZJdVlhU29lN1hJZzlcbkliTnVkZm5URzdTQ0JJR2dBSjRBSUpJTk1ZVjduZFpHMEdYWVpMbjFFMHRYcE84RnZjRVRSL3U2Q0pWeGc3VGdcbkFCQ0hmcWlZNzk2ak52VGRzbFhDUzR5Y21MdGpOWm1UeUhDWGx4WkpSQjhDSm1QKzBMTlNIWmhVR3VQaTBPM0ZcbmJsRmZYekJVTDZTMXpJaS82dGdpMFo4RytwWDNpeDhicGZpclJ3MTc4aDlyb2NrTlY2V1VzMFFyTWduMjRHWVdcblZzKzREM2syY0dTVngrMHFiM3YwTGlkMFcva3BoOHVPUDg3TVpBPT1cbi0tLS0tRU5EIFRTUzIgUFJJVkFURSBLRVktLS0tLVxuIn0="
  }
}
WrappingKey: {"pcrs":{},"tpmKey":"-----BEGIN TSS2 PRIVATE KEY-----\nMIIBCAYGZ4EFCgEDoAMBAf8CBEAAAAEEUABOAAgACwAAABIAIOG6xjh/qY92SYVS\nt+A7aum7ThFxU0xZ7q7A9MyLxDfmABAAIHVy1AxXu0HEH+nIjujFIuYaSoe7XIg9\nIbNudfnTG7SCBIGgAJ4AIJINMYV7ndZG0GXYZLn1E0tXpO8FvcETR/u6CJVxg7Tg\nABCHfqiY796jNvTdslXCS4ycmLtjNZmTyHCXlxZJRB8CJmP+0LNSHZhUGuPi0O3F\nblFfXzBUL6S1zIi/6tgi0Z8G+pX3ix8bpfirRw178h9rockNV6WUs0QrMgn24GYW\nVs+4D3k2cGSVx+0qb3v0Lid0W/kph8uOP87MZA==\n-----END TSS2 PRIVATE KEY-----\n"}

Encrypted: BdNE9boW0a91verJDCdq1ecjn30c6FwYz/gqxbLUTQ==
Decrypted: foo
```


##### Testing

##### Test Setup

These tests uses a softwareTPM which can be found [here](https://github.com/stefanberger/swtpm).  

First initialize it:

```bash
rm -rf /tmp/myvtpm && \
mkdir /tmp/myvtpm && \
swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

export TPM2TOOLS_TCTI="swtpm:port=2321"
```

##### Running tests

Now that you've completed the required setup, you can run the tests via:

```shell
export VAULT_ACC=true
go test -v
```

You should see

```shell
$ go test -v
=== RUN   TestDisableEnv
--- PASS: TestDisableEnv (0.01s)
=== RUN   TestTPMSeal
=== RUN   TestTPMSeal/config
--- PASS: TestTPMSeal (0.00s)
    --- PASS: TestTPMSeal/config (0.00s)
=== RUN   TestTPMSeal_Lifecycle
--- PASS: TestTPMSeal_Lifecycle (0.01s)
=== RUN   TestTPMSeal_Lifecycle_UserAuth_Pass
--- PASS: TestTPMSeal_Lifecycle_UserAuth_Pass (0.01s)
=== RUN   TestTPMSeal_Lifecycle_UserAuth_Fail
--- PASS: TestTPMSeal_Lifecycle_UserAuth_Fail (0.01s)
=== RUN   TestTPMSeal_Lifecycle_PCR_Pass
--- PASS: TestTPMSeal_Lifecycle_PCR_Pass (0.01s)
=== RUN   TestTPMSeal_Lifecycle_PCR_Fail
--- PASS: TestTPMSeal_Lifecycle_PCR_Fail (0.00s)
PASS
ok  	github.com/openbao/go-kms-wrapping/wrappers/tpm/v2	0.066s
```

Note that the `TestTPMSeal_Lifecycle_PCR_Fail` changes the value of PCR=23.  What that means is you must restart the software TPM again to rerun the test suite.  Alternatively, you can skip just that one:

```shell
go test -v -count=1  -skip '^(TestTPMSeal_Lifecycle_PCR_Fail)'
```