# Azure Key Vault Wrapper

This wrapper provides integration with [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) for encryption operations.

## Features

- Envelope encryption for large payloads
- Support for RSA and EC keys
- Additional Authenticated Data (AAD) support
- Multiple authentication methods (Service Principal, Managed Identity, CLI)
- Automatic retry with exponential backoff
- Hardware Security Module (HSM) support

## Configuration

### Configuration Parameters

| Parameter | Environment Variable | Description | Default | Required |
|-----------|---------------------|-------------|---------|----------|
| `vault_name` | `AZURE_KEY_VAULT_NAME` | Name of the Key Vault | - | Yes |
| `key_name` | `AZURE_KEY_NAME` | Name of the key in Key Vault | - | Yes |
| `key_version` | `AZURE_KEY_VERSION` | Specific key version | Latest | No |
| `tenant_id` | `AZURE_TENANT_ID` | Azure AD tenant ID | - | Yes* |
| `client_id` | `AZURE_CLIENT_ID` | Service principal client ID | - | Yes* |
| `client_secret` | `AZURE_CLIENT_SECRET` | Service principal secret | - | No** |
| `client_cert_path` | `AZURE_CLIENT_CERT_PATH` | Path to client certificate | - | No** |
| `client_cert_password` | `AZURE_CLIENT_CERT_PASSWORD` | Client certificate password | - | No |
| `resource` | `AZURE_AD_RESOURCE` | Resource for token acquisition | `https://vault.azure.net` | No |
| `environment` | `AZURE_ENVIRONMENT` | Azure environment | `AzurePublicCloud` | No |

\* Not required when using Managed Identity or Azure CLI authentication
\** Either client_secret or client_cert_path required for Service Principal auth

### Authentication Methods

The wrapper supports multiple authentication methods:

1. **Service Principal with Secret**
2. **Service Principal with Certificate**
3. **Managed Identity** (for Azure VMs, AKS, etc.)
4. **Azure CLI** (for local development)

## Usage Examples

### Basic Usage with Service Principal

```go
package main

import (
    "context"
    "log"
    
    "github.com/openbao/go-kms-wrapping/v2/wrappers/azurekeyvault"
    "github.com/openbao/go-kms-wrapping/v2"
)

func main() {
    ctx := context.Background()
    
    // Create wrapper
    wrapper := azurekeyvault.NewWrapper()
    
    // Configure with Key Vault
    _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
        "vault_name":    "my-key-vault",
        "key_name":      "my-encryption-key",
        "tenant_id":     "12345678-1234-1234-1234-123456789012",
        "client_id":     "87654321-4321-4321-4321-210987654321",
        "client_secret": "super-secret-value",
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
    
    log.Printf("Decrypted: %s", decrypted)
}
```

### Using Managed Identity

```go
// On Azure VM, AKS, or other Azure services
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "vault_name": "my-key-vault",
    "key_name":   "my-encryption-key",
    // No tenant_id, client_id, or client_secret needed
}))
```

### Using System-Assigned Managed Identity with Specific Resource

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "vault_name": "my-key-vault",
    "key_name":   "my-encryption-key",
    "resource":   "https://vault.azure.net",
}))
```

### Using User-Assigned Managed Identity

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "vault_name": "my-key-vault",
    "key_name":   "my-encryption-key",
    "client_id":  "87654321-4321-4321-4321-210987654321", // Managed identity client ID
}))
```

### Service Principal with Certificate

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "vault_name":            "my-key-vault",
    "key_name":              "my-encryption-key",
    "tenant_id":             "12345678-1234-1234-1234-123456789012",
    "client_id":             "87654321-4321-4321-4321-210987654321",
    "client_cert_path":      "/path/to/certificate.pfx",
    "client_cert_password":  "cert-password",
}))
```

### With Additional Authenticated Data

```go
// Encrypt with AAD
aad := []byte("transaction-id-12345")
encrypted, err := wrapper.Encrypt(ctx, plaintext, wrapping.WithAad(aad))

// Must provide same AAD for decryption
decrypted, err := wrapper.Decrypt(ctx, encrypted, wrapping.WithAad(aad))
```

### Using HSM-backed Keys

```go
// Keys in Premium Key Vaults are HSM-backed
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "vault_name":    "my-premium-vault",
    "key_name":      "my-hsm-key",
    "tenant_id":     "12345678-1234-1234-1234-123456789012",
    "client_id":     "87654321-4321-4321-4321-210987654321",
    "client_secret": "super-secret-value",
}))
```

## Key Vault Setup

### Create Key Vault and Key

```bash
# Create resource group
az group create --name myResourceGroup --location eastus

# Create Key Vault
az keyvault create \
  --name my-key-vault \
  --resource-group myResourceGroup \
  --location eastus

# Create key
az keyvault key create \
  --vault-name my-key-vault \
  --name my-encryption-key \
  --kty RSA \
  --size 2048
```

### Configure Access Policy

```bash
# For Service Principal
az keyvault set-policy \
  --name my-key-vault \
  --spn 87654321-4321-4321-4321-210987654321 \
  --key-permissions get list encrypt decrypt wrapKey unwrapKey

# For Managed Identity
az keyvault set-policy \
  --name my-key-vault \
  --object-id <managed-identity-object-id> \
  --key-permissions get list encrypt decrypt wrapKey unwrapKey
```

## Testing

### Unit Tests

```bash
go test ./wrappers/azurekeyvault
```

### Integration Tests

Integration tests require Azure credentials and a Key Vault:

```bash
export AZURE_TENANT_ID="12345678-1234-1234-1234-123456789012"
export AZURE_CLIENT_ID="87654321-4321-4321-4321-210987654321"
export AZURE_CLIENT_SECRET="super-secret-value"
export AZURE_KEY_VAULT_NAME="my-key-vault"
export AZURE_KEY_NAME="my-encryption-key"

go test ./wrappers/azurekeyvault -tags=integration
```

### Local Development with Azure CLI

```bash
# Login with Azure CLI
az login

# Run tests using CLI authentication
export AZURE_KEY_VAULT_NAME="my-key-vault"
export AZURE_KEY_NAME="my-encryption-key"

go test ./wrappers/azurekeyvault
```

## Performance Considerations

### Connection Pooling

The Azure SDK manages connection pooling automatically. You can tune HTTP client settings:

```go
import "net/http"

// Custom HTTP client with tuned settings
httpClient := &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
    },
}
```

### Token Caching

Authentication tokens are cached automatically by the Azure SDK. Token refresh happens transparently before expiration.

### Envelope Encryption

For large payloads, the wrapper automatically uses envelope encryption:

1. Generates a data encryption key (DEK)
2. Encrypts the plaintext with AES-GCM using the DEK
3. Encrypts the DEK with Key Vault
4. Returns both encrypted DEK and encrypted data

## Security Best Practices

1. **Use Managed Identity**: When running on Azure, prefer Managed Identity over Service Principal

2. **Least Privilege Access**: Grant minimum required permissions
   ```bash
   # Minimum permissions for encryption/decryption
   az keyvault set-policy \
     --name my-key-vault \
     --spn $CLIENT_ID \
     --key-permissions get encrypt decrypt wrapKey unwrapKey
   ```

3. **Enable Soft Delete**: Protect against accidental key deletion
   ```bash
   az keyvault update \
     --name my-key-vault \
     --enable-soft-delete true \
     --retention-days 90
   ```

4. **Use Private Endpoints**: Keep traffic within Azure network
   ```bash
   az network private-endpoint create \
     --name myPrivateEndpoint \
     --resource-group myResourceGroup \
     --vnet-name myVNet \
     --subnet mySubnet \
     --private-connection-resource-id $(az keyvault show --name my-key-vault --query id -o tsv) \
     --group-id vault \
     --connection-name myConnection
   ```

5. **Enable Logging**: Monitor Key Vault access
   ```bash
   az monitor diagnostic-settings create \
     --name myDiagSetting \
     --resource $(az keyvault show --name my-key-vault --query id -o tsv) \
     --logs '[{"category": "AuditEvent", "enabled": true}]' \
     --workspace myLogAnalyticsWorkspace
   ```

## Troubleshooting

### Common Errors

1. **AADSTS700016: Application not found**
   - Verify client_id is correct
   - Check tenant_id matches your Azure AD tenant
   - Ensure Service Principal exists

2. **Forbidden: The user, group or application does not have secrets get permission**
   - Check Key Vault access policies
   - Verify the identity has required permissions
   - For Managed Identity, ensure it's properly configured

3. **ResourceNotFound: The key was not found**
   - Verify key_name is correct
   - Check Key Vault name and region
   - Ensure key is enabled

### Debug Logging

Enable Azure SDK logging:

```go
import (
    "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
)

// Enable logging
log.SetListener(func(event log.Event, msg string) {
    fmt.Printf("[%s] %s\n", event, msg)
})

// Set log events to monitor
log.SetEvents(log.EventRequest, log.EventResponse)
```

### Verify Configuration

```bash
# Test Key Vault access
az keyvault key show \
  --vault-name my-key-vault \
  --name my-encryption-key

# Test encryption
echo "test data" | az keyvault key encrypt \
  --vault-name my-key-vault \
  --name my-encryption-key \
  --algorithm RSA-OAEP-256
```

## Additional Resources

- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go)
- [Azure Key Vault Best Practices](https://docs.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [OpenBao Auto-Unseal with Azure Key Vault](https://openbao.org/docs/configuration/seal/azurekeyvault)