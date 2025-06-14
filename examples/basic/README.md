# Basic Usage Example

This example demonstrates basic encryption and decryption using different KMS providers.

## Usage

```bash
# AEAD (local encryption) - no setup required
go run main.go -provider=aead -plaintext="Hello, World!"

# AWS KMS
export AWS_REGION=us-east-1
export AWS_KMS_KEY_ID=alias/my-key
go run main.go -provider=awskms -plaintext="Hello, World!"

# Azure Key Vault
export AZURE_KEY_VAULT_NAME=my-vault
export AZURE_KEY_NAME=my-key
go run main.go -provider=azurekeyvault -plaintext="Hello, World!"

# Google Cloud KMS
export GCP_KMS_KEY_RING=projects/my-project/locations/global/keyRings/my-ring
export GCP_KMS_CRYPTO_KEY=my-key
go run main.go -provider=gcpckms -plaintext="Hello, World!"
```

## With Additional Authenticated Data (AAD)

```bash
go run main.go -provider=aead -plaintext="Secret data" -aad="context-info"
```

## Environment Variables

### AWS KMS
- `AWS_REGION`: AWS region (default: us-east-1)
- `AWS_KMS_KEY_ID`: KMS key ID, ARN, or alias
- `AWS_ENDPOINT`: Custom endpoint (for LocalStack)

### Azure Key Vault
- `AZURE_KEY_VAULT_NAME`: Key Vault name
- `AZURE_KEY_NAME`: Key name
- `AZURE_TENANT_ID`: Azure AD tenant ID (optional for Managed Identity)
- `AZURE_CLIENT_ID`: Service principal client ID (optional)
- `AZURE_CLIENT_SECRET`: Service principal secret (optional)

### Google Cloud KMS
- `GCP_KMS_KEY_RING`: Full key ring resource name
- `GCP_KMS_CRYPTO_KEY`: Crypto key name
- `GOOGLE_APPLICATION_CREDENTIALS`: Path to service account JSON (optional)