# Go-KMS-Wrapping - Go library for encrypting values through various KMS providers

[![Go Reference](https://pkg.go.dev/badge/github.com/openbao/go-kms-wrapping/v2.svg)](https://pkg.go.dev/github.com/openbao/go-kms-wrapping/v2)
[![Go Report Card](https://goreportcard.com/badge/github.com/openbao/go-kms-wrapping)](https://goreportcard.com/report/github.com/openbao/go-kms-wrapping)
[![License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)

> **Note**: This is version 2 of the library. The `v0` branch contains version 0, which may be needed for legacy applications or while transitioning to version 2.

## Overview

Go-KMS-Wrapping is a Go library that provides a unified interface for encrypting data using various Key Management Service (KMS) providers. It enables applications to leverage cloud KMS services, hardware security modules, and software-based encryption through a consistent API.

This library is the cryptographic foundation of [OpenBao's auto-unseal](https://openbao.org/docs/concepts/seal#auto-unseal) functionality and is production-ready for securing sensitive data across multiple platforms.

### Key Concepts

- **Envelope Encryption**: For KMS providers with size limitations, the library automatically implements envelope encryption using authenticated encryption with associated data (AEAD)
- **Provider Agnostic**: Write once, encrypt anywhere - switch between KMS providers through configuration
- **Key Rotation**: Built-in support for key versioning and rotation without re-encrypting existing data
- **Plugin Architecture**: Optional plugin system to avoid direct dependencies on KMS SDKs

## Table of Contents

- [Features](#features)
- [Supported Providers](#supported-providers)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Provider Configuration](#provider-configuration)
- [Advanced Features](#advanced-features)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **🔐 Multiple KMS Support**: Integrate with major cloud providers and on-premise solutions
- **🔄 Automatic Envelope Encryption**: Handle large payloads transparently
- **🔑 Key Rotation**: Support multiple key versions for decryption
- **🧩 Plugin System**: Load KMS providers as external plugins
- **🛡️ AAD Support**: Additional Authenticated Data for enhanced security
- **🏃 Zero Downtime Migration**: Switch providers without service interruption
- **📦 Minimal Dependencies**: Core library has minimal external dependencies

## Supported Providers

### Cloud Providers
| Provider | Envelope Encryption | AAD Support | Auto-Unseal | Documentation |
|----------|-------------------|-------------|-------------|---------------|
| **AWS KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/awskms/) |
| **Azure Key Vault** | ✅ | ✅ | ✅ | [Guide](wrappers/azurekeyvault/) |
| **Google Cloud KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/gcpckms/) |
| **Alibaba Cloud KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/alicloudkms/) |
| **Huawei Cloud KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/huaweicloudkms/) |
| **OCI KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/ocikms/) |
| **Tencent Cloud KMS** | ✅ | ✅ | ✅ | [Guide](wrappers/tencentcloudkms/) |

### Software/Hardware Solutions
| Provider | Envelope Encryption | AAD Support | Auto-Unseal | Documentation |
|----------|-------------------|-------------|-------------|---------------|
| **OpenBao Transit** | ❌ | ❌ | ✅ | [Guide](wrappers/transit/) |
| **PKCS#11 HSM** | Device-dependent | ✅ | ✅ | [Guide](wrappers/pkcs11/) |
| **KMIP** | Server-dependent | ✅ | ✅ | [Guide](wrappers/kmip/) |
| **AEAD (AES-GCM)** | ❌ | ✅ | ❌ | [Guide](wrappers/aead/) |

## Installation

```bash
go get github.com/openbao/go-kms-wrapping/v2
```

### Minimum Requirements
- Go 1.21 or higher
- Provider-specific requirements (see individual provider documentation)

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/openbao/go-kms-wrapping/v2/wrappers/awskms"
    "github.com/openbao/go-kms-wrapping/v2"
)

func main() {
    ctx := context.Background()
    
    // Create a new AWS KMS wrapper
    wrapper := awskms.NewWrapper()
    
    // Configure with KMS key
    _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
        "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
        "region":     "us-east-1",
    }))
    if err != nil {
        log.Fatal(err)
    }
    
    // Encrypt data
    plaintext := []byte("sensitive data")
    encrypted, err := wrapper.Encrypt(ctx, plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt data
    decrypted, err := wrapper.Decrypt(ctx, encrypted)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Successfully encrypted and decrypted: %s", decrypted)
}
```

### Using with Additional Authenticated Data (AAD)

```go
// Encrypt with AAD
encrypted, err := wrapper.Encrypt(ctx, plaintext, wrapping.WithAad([]byte("metadata")))

// Decrypt with same AAD
decrypted, err := wrapper.Decrypt(ctx, encrypted, wrapping.WithAad([]byte("metadata")))
```

## Usage Guide

### Provider Selection

Choose a provider based on your requirements:

```go
// Cloud KMS (recommended for cloud deployments)
wrapper := awskms.NewWrapper()      // AWS
wrapper := azurekeyvault.NewWrapper() // Azure
wrapper := gcpckms.NewWrapper()      // Google Cloud

// On-premise or hybrid
wrapper := transit.NewWrapper()      // OpenBao Transit
wrapper := pkcs11.NewWrapper()       // Hardware Security Module

// Development/testing
wrapper := aead.NewWrapper()         // Local AES-GCM encryption
```

### Configuration Methods

#### 1. Configuration Map (Recommended)

```go
config := map[string]string{
    "kms_key_id": "projects/PROJECT_ID/locations/global/keyRings/RING/cryptoKeys/KEY",
    "credentials": "/path/to/service-account.json",
}

_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
```

#### 2. Environment Variables

```bash
export AWSKMS_WRAPPER_KEY_ID="arn:aws:kms:..."
export AWS_REGION="us-east-1"
```

```go
// Wrapper will automatically read environment variables
_, err := wrapper.SetConfig(ctx)
```

#### 3. Provider-Specific Options

```go
import "github.com/openbao/go-kms-wrapping/v2/wrappers/awskms"

_, err := wrapper.SetConfig(ctx, 
    awskms.WithRegion("us-east-1"),
    awskms.WithKeyId("alias/my-key"),
    awskms.WithEndpoint("http://localhost:4566"), // LocalStack
)
```

### Error Handling

```go
encrypted, err := wrapper.Encrypt(ctx, data)
if err != nil {
    switch {
    case errors.Is(err, wrapping.ErrInvalidParameter):
        // Handle invalid input
    case errors.Is(err, context.DeadlineExceeded):
        // Handle timeout
    default:
        // Handle other errors
    }
}
```

## Provider Configuration

### AWS KMS

```go
// Using IAM role
config := map[string]string{
    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/...",
    "region":     "us-east-1",
}

// Using access keys (not recommended for production)
config := map[string]string{
    "kms_key_id":        "alias/my-key",
    "region":            "us-east-1",
    "access_key":        "AKIAIOSFODNN7EXAMPLE",
    "secret_key":        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

// Using STS assume role
config := map[string]string{
    "kms_key_id": "alias/my-key",
    "region":     "us-east-1",
    "role_arn":   "arn:aws:iam::123456789012:role/KMSRole",
}
```

### Azure Key Vault

```go
config := map[string]string{
    "vault_name":    "my-key-vault",
    "key_name":      "my-key",
    "tenant_id":     "12345678-1234-1234-1234-123456789012",
    "client_id":     "87654321-4321-4321-4321-210987654321",
    "client_secret": "super-secret-value",
}

// Using managed identity
config := map[string]string{
    "vault_name": "my-key-vault",
    "key_name":   "my-key",
    "resource":   "https://vault.azure.net", // Optional custom resource
}
```

### Google Cloud KMS

```go
config := map[string]string{
    "key_ring":    "projects/my-project/locations/global/keyRings/my-ring",
    "crypto_key":  "my-key",
    "credentials": "/path/to/service-account.json",
}

// Using Application Default Credentials
config := map[string]string{
    "key_ring":   "projects/my-project/locations/global/keyRings/my-ring",
    "crypto_key": "my-key",
    // No credentials path needed when using ADC
}
```

### OpenBao Transit

```go
config := map[string]string{
    "address":     "https://openbao.example.com:8200",
    "token":       "hvs.CAESIJfU...",
    "key_name":    "my-transit-key",
    "mount_path":  "transit", // Optional, defaults to "transit"
    "tls_ca_cert": "/path/to/ca.pem",
}
```

## Advanced Features

### Plugin Architecture

Use wrappers as external plugins to avoid dependencies:

```go
// Build a plugin
// See examples/plugin-cli for complete example

// In your application
client := plugin.NewPluginClient(&plugin.ClientConfig{
    HandshakeConfig: wrapping.PluginHandshakeConfig,
    Plugins: map[string]plugin.Plugin{
        "wrapper": &wrapping.PluginWrapper{},
    },
    Cmd: exec.Command("./path/to/plugin"),
})

// Use the plugin wrapper
raw, err := client.Dispense("wrapper")
wrapper := raw.(wrapping.Wrapper)
```

### Multi-Wrapper (Key Rotation)

```go
import "github.com/openbao/go-kms-wrapping/v2/extras/multi"

// Create multi-wrapper for key rotation
multiWrapper := multi.NewWrapper(&multi.WrapperConfig{
    Wrappers: map[string]wrapping.Wrapper{
        "v1": oldWrapper,
        "v2": newWrapper,
    },
    CurrentKeyID: "v2", // Encrypt with v2
})

// Automatically decrypts with appropriate key version
plaintext, err := multiWrapper.Decrypt(ctx, encrypted)
```

### Performance Optimization

```go
// Connection pooling for cloud providers
config := map[string]string{
    "kms_key_id":          "arn:aws:kms:...",
    "max_retries":         "3",
    "max_connections":     "100",
    "connection_timeout":  "30s",
}

// Batch operations (provider-specific)
// Example with custom wrapper implementation
type BatchWrapper interface {
    wrapping.Wrapper
    EncryptBatch(ctx context.Context, batch [][]byte) ([]*wrapping.BlobInfo, error)
}
```

## Security Considerations

### Best Practices

1. **Key Management**
   - Use separate keys for different environments
   - Implement key rotation policies
   - Never delete keys that may have encrypted data

2. **Access Control**
   - Use IAM roles instead of access keys
   - Apply principle of least privilege
   - Enable audit logging

3. **Error Handling**
   - Don't log sensitive data
   - Implement proper retry logic
   - Handle key unavailability gracefully

4. **Compliance**
   - Ensure KMS configuration meets compliance requirements
   - Use appropriate key algorithms and sizes
   - Implement proper key lifecycle management

### Security Checklist

- [ ] KMS keys are properly configured with access policies
- [ ] Using IAM roles/managed identities where possible
- [ ] Audit logging enabled for all KMS operations
- [ ] Implementing key rotation strategy
- [ ] Not storing encrypted data with plaintext
- [ ] Using AAD where appropriate
- [ ] Monitoring for anomalous encryption/decryption patterns

## Troubleshooting

### Common Issues

#### "Key not found" errors
```go
// Ensure key exists and has proper permissions
// Check key ARN/ID format for your provider
```

#### Timeout errors
```go
// Increase context timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
```

#### Permission denied
```go
// Verify IAM/RBAC permissions
// Check: kms:Encrypt, kms:Decrypt, kms:GenerateDataKey
```

### Debug Logging

```go
// Enable debug logging for providers
wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "debug": "true",
}))
```

## Examples

- [Basic Usage](examples/basic) - Simple encrypt/decrypt example
- [Plugin CLI](examples/plugin-cli) - Complete plugin implementation
- [Multi-Provider](examples/multi-provider) - Using multiple providers
- [Key Rotation](examples/key-rotation) - Implementing key rotation
- [Batch Operations](examples/batch) - Batch encryption example

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

```bash
# Clone the repository
git clone https://github.com/openbao/go-kms-wrapping.git
cd go-kms-wrapping

# Install dependencies
go mod download

# Run tests
make test

# Run linters
make lint
```

### Testing with Providers

See provider-specific testing guides:
- [AWS KMS with LocalStack](wrappers/awskms/README.md#testing)
- [GCP KMS Testing Guide](wrappers/gcpckms/how-to-test-gcp-kms.md)
- [PKCS#11 with SoftHSM](wrappers/pkcs11/README.md#testing)

## Related Projects

- [OpenBao](https://github.com/openbao/openbao) - Open source secrets management
- [go-plugin](https://github.com/hashicorp/go-plugin) - Go plugin system over RPC

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).