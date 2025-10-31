# Securosys KMS
This kms implements a platform-agnostic REST-based HSM interface with zero library installation
- Manage keys RSA/EC/AES keys
- Perform cryptographic operations on the HSM

This plugin is actively maintained by Securosys SA.

## Table of Contents

- [Glossary](#glossary)
- [How to run](#how-to-run)
    - [Configure the KMS](#configure-the-kms)
        - [MetaData Signature](#metadata-signature)
        - [TSB ApiKeys](#tsb-apikeys)
- [Appendix](#appendix)
    - [Frequently Asked Questions](#frequently-asked-questions)
    - [Full Policy JSON example](#full-policy-json-example)

---


## How to run
### Configure the KMS
Configure the KMS for accessing the Securosys Primus HSM or CloudsHSM.

Required attributes:
- `auth` - Attribute defines the authorization type to TSB. Values for this attribute can be `TOKEN`, `CERT` or `NONE`
- `restapi` - REST API URL to access the REST/TSB endpoint (available from your Security Officer or CloudsHSM service provider)

Define additional attributes based on the selected authorization type `auth`:
1.  `TOKEN`
    Add the attribute `bearertoken` with the JWT token
1.  `CERT`
    Setup `certpath` with local PATH to the certificate and `keypath` with local PATH to the key.
1.  `NONE`
    No additional attributes required.

**Example for disabled authorization**:
```golang
var provider = map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "NONE",
	
}

```

**Example for JWT token authorization**:
```golang
var provider = map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "TOKEN",
		"bearertoken":  "jwt token string",
	
}
```
**Example for Certificate authorization**:
```golang
var provider = map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "CERT",
		"certpath":  "local_absolute_path_to_certificate.pem",
        "keypath":  "local_absolute_path_to_private.key",
	
}
```

Full example:
```golang
	var provider := map[string]interface{}{
			"restapi": "demo",
			"auth":    "NONE",
		
	}
	keystore, err := securosyshsm.NewKeyStore(provider)
```

#### MetaData signature

Additionally there is a option to generate signature for metadata on all asynchronous requests.
**applicationKeyPair** option is using to provide RSA public key and private key.
Using this key will be generated signature for metadata.
format ```'{\"privateKey\":\"private_key_string\",\"publicKey\":\"public_key_string\"}'```
> **Note:** You have to provide **private key** and **public key** without headers

Example:
```golang
var provider =  map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "NONE",
		"applicationKeyPair": "{\"privateKey\":\"MIIEvgIBADANBg...\",\"publicKey\":\"MIIBIjANBgkqh...\"}",
	
}
```
### Example run the KMS
```golang
package main

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"os"
	securosyshsm "github.com/openbao/go-kms-wrapping/keystores/securosyshsm/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func main() {
	ctx := context.Background()
	provider := map[string]interface{}{
		"restapi": "TSB URL",
		"auth":    "NONE",
		//"applicationKeyPair": "{\"privateKey\":\"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDK2cG1SMP0OaJC9zVEUYZGu9d1mrz9WVm2wXd/oUm/5K6AO0Y/324bm2pWegaRME7oFZvwPc3LSY9NQyjX6G2FT7PZZ1r/86Ak4p7veTHsmXnM+7Fv68U7S9Za4qpMXEtigqKSwBb7+XjIEiJtZVT3wclsxL/XCye6Y72DuxokmkpJh+yABzIYukos//Bh8Kh12Q3IOxerJlu/HJF6TknSO7xR1DtlPBFOuxo7JZKvJrbAAZ0GmjT5WkpE7GBcc4+ODM0HFPxAHgbt5eZp7+huWF+CoZCC0d/2TaVPf/LvvcTp1DKjxclYuugEF24S5HIpKfK3UKB+nik29j5sVjBFAgMBAAECggEAJ+zSHn8y6kfJswp69nZhSlzAXIpXNjo22Syc+4bgQB+fZOfFvN6aCl79gAXGcx8h+LYAGjnf3modBWT5jf1WSQ3V5S1dkND/rSLZi2K8O8g9W+YSF2g9Sp1zlDHWuO7Ve48gtmeOXovMhPxkwElYfucqYPkclRPB/wKQk3PpAljtv2JfI0a0BqA3uOZFNzonb5SROf6gaBJU3omW0j/jo1/ZMOXMkvtokrUhc4PIBBeKhZBxSr9NlFYB/sweyY7uxvviY/Phrph2azDVTNGDk7TZoBXpmdly3GdavdPGq8po03hPN2oy4yObWtaQnJuw2/4HXWsW6A0aKy9Qv76ShQKBgQD5vhWb2sYr6zBLi1MjUYu1dLuImo2m22NBfk1QPa8FsW/Z8MqSjJGIVtZHPVG1gpRl/tXyUAdaIcdnksLQwTQI1JVe5gaZZodxFSfs7azSP7ctHKCfRNSSqt2Ly62EiiyjUWsrL8o/UxwTQGHR4hJnGxqq2AGFNcFLLZRPGXtDtwKBgQDP7uUd3YWgovxc9apgofsdUoaNPqtE+gVAiic1GAz/6RPgTNqiQvv0RqukrUQa8F21xWsedEZH042Zi619J9OTEhZ+EbCKDqKShPH2b5qK1eMzIlECZO1kCqyrFdyzq2zMxhgfBC3S/ab1V/bgVxQaV8++uV+Snmu86DqzG7ID4wKBgF9sivMnL4s+bRCgZp7bHKezt6glbbRwpUc0DDR5rTNerd83Sx+dyEmw7GUCAAN7plomefcBLx34RCnGANwkxk4NdBlziNf6PgwuSjgURHF9WO9KvfC9Kv/ze31b0KwQ46dvh6RTuVJi3hpZAkdguylcSN84c7RDatzfyIhEsz2XAoGBAMJdAHXmN55sO5F5YYVqZByIo5Ur21RikL4/ZV7P2HbuG9IyhLvf+TvhQ1hvTZYQ0Me0fei9r2Q8b8PzOHwg2jhDVBsL1gV2oKhs9O/yancUb4fAsBCY3v4ArF5P1TltKApRsQJtGZh72bDERNR3ESd+pYYWKSwYQYUXXqdFYCUZAoGBALqPi0VfUymHsN91mK+73j8BDX+me1sYgGELHq06m3fc2zToJLhXfE2hwQRdWLcHFJVvI0TP20YLWONCcNt8OAudmCpdg85tRqV7Yndll4Hu+sj+RLX3nwIcEDgnzchXcZRtVQdbnWAVDLjq4vkj4CB01MioPnqhtfdPCA57JI4M\",\"publicKey\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAytnBtUjD9DmiQvc1RFGGRrvXdZq8/VlZtsF3f6FJv+SugDtGP99uG5tqVnoGkTBO6BWb8D3Ny0mPTUMo1+hthU+z2Wda//OgJOKe73kx7Jl5zPuxb+vFO0vWWuKqTFxLYoKiksAW+/l4yBIibWVU98HJbMS/1wsnumO9g7saJJpKSYfsgAcyGLpKLP/wYfCoddkNyDsXqyZbvxyRek5J0ju8UdQ7ZTwRTrsaOyWSrya2wAGdBpo0+VpKROxgXHOPjgzNBxT8QB4G7eXmae/oblhfgqGQgtHf9k2lT3/y773E6dQyo8XJWLroBBduEuRyKSnyt1Cgfp4pNvY+bFYwRQIDAQAB\"}",
	}
	keystore, err := securosyshsm.NewKeyStore(provider)
	//fmt.Println(keystore.GenerateRandom(100))
	if err != nil {
		return
	}
	key, err := keystore.GetKeyByName(ctx, "AES_KEY_OPENBAO_TEST")
	if key == nil {
		key, err = keystore.GenerateSecretKey(ctx, &kms.KeyAttributes{
			KeyType:     kms.KeyType_AES,
			Name:        "AES_KEY_OPENBAO_TEST",
			BitKeyLen:   256,
			IsRemovable: true,
			CanDecrypt:  true,
			CanEncrypt:  true,
		})
	}
	if err != nil {
		return
	}
	ctx = securosyshsm.WithSecretKey(ctx, key.(*securosyshsm.SecretKey))
	encrypt, err := securosyshsm.CipherFactory{}.NewCipher(ctx, kms.CipherOp_Encrypt, &kms.CipherParameters{
		Algorithm:  kms.CipherMode_AES_GCM,
		Parameters: kms.AESGCMCipherParameters{AAD: nil},
	})
	if err != nil {
		return
	}
	decodeString, err := b64.StdEncoding.DecodeString("dGVzdA==")
	if err != nil {
		return
	}
	output, err := encrypt.Close(ctx, decodeString)
	if err != nil {
		return
	}
	
	decrypt, err := securosyshsm.CipherFactory{}.NewCipher(ctx, kms.CipherOp_Decrypt, &kms.CipherParameters{
		Algorithm:  kms.CipherMode_AES_GCM,
		Parameters: kms.AESGCMCipherParameters{AAD: nil},
	})
	if err != nil {
		return
	}
	decrypted, err := decrypt.Close(ctx, output)
	if err != nil {
		return
	}
	fmt.Println(string(decrypted))
}
```

#### TSB ApiKeys
KMS engine use only 3 of TSB api keys:
- **ServiceToken** - for health check
- **KeyManagementToken** - for creating/listing/deleting keys
- **KeyOperationToken** - for operations on keys like decrypt/encrypt, sign/verify etc.

> **Structure for api keys**: There is a option to provide multiple api keys per single **token**. Plugin will check witch one of the list is correct one, and use only working  token for operation.

```
"apiKeys":"{\"KeyManagementToken\":[\"tsb-x-token_key_management1\",\"tsb-x-token_key_management2\",\"tsb-x-token_key_management3\" ...],\"KeyOperationToken\":[\tsb-x-token_key_operation\"],\"ServiceToken\":[\"tsb-x-token_service\"]}" 
```

Plugin configuration with api keys:
```golang
var provider = map[string]interface{}{
		"restapi": "TSB_URL",
		"auth":    "NONE",
		"applicationKeyPair": "{\"privateKey\":\"MIIEvgIBADANBg...\",\"publicKey\":\"MIIBIjANBgkqh...\"}",
		"apiKeys": "{\"KeyManagementToken\":[\"tsb-x-token_key_management\"],\"KeyOperationToken\":[\tsb-x-token_key_operation\"],\"ServiceToken\":[\"tsb-x-token_service\"]}"

}
```

---
## Appendix
### Frequently Asked Questions
1) > **Why I don't get a public key and policy on some key types**
   Some key types are symmetric, and therefore don't have a public key nor a SKA policy.
   
### Full Policy JSON Example
```json
{
  "ruleUse": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleBlock": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleUnblock": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "ruleModify": {
    "tokens": [
      {
        "name": "Token Name",
        "timelock": 0,
        "timeout": 0,
        "groups": [
          {
            "name": "Group Name",
            "quorum": 1,
            "approvals": [
              {
                "type": "public_key",
                "name": "Name",
                "value": "RSA_PUBLIC_KEY"
              }
            ]
          }
        ]
      }
    ]
  },
  "keyStatus": {
    "blocked": false
  }
}
```
