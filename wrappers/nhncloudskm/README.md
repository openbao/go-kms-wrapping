# NHN Cloud SKM wrapper

Provides integration with NHN Cloud Secure Key Manager (SKM) for encryption and decryption operations using envelope encryption.

## Settings

| Environment variable                    | Required | Default                                      | Description                                    |
| --------------------------------------- | -------- | -------------------------------------------- | ---------------------------------------------- |
| NHN_CLOUD_SKM_KEY_ID                   | yes      |                                              | Symmetric key ID for encryption operations    |
| NHN_CLOUD_SKM_APP_KEY                  | yes      |                                              | NHN Cloud project app key                     |
| NHN_CLOUD_SKM_USER_ACCESS_KEY_ID       | yes      |                                              | NHN Cloud user access key ID                  |
| NHN_CLOUD_SKM_USER_SECRET_ACCESS_KEY   | yes      |                                              | NHN Cloud user secret access key              |
| NHN_CLOUD_SKM_ENDPOINT                 | no       | https://api-keymanager.nhncloudservice.com   | NHN Cloud SKM API endpoint                     |
| NHN_CLOUD_SKM_MAC_ADDRESS              | no       |                                              | Client MAC address for additional security     |

## Features

### Envelope Encryption
The NHN Cloud SKM wrapper uses envelope encryption to handle data of any size:

1. **Data Encryption Key (DEK)**: A 32-byte AES-256 key is generated for each encryption operation
2. **Data Encryption**: The actual data is encrypted using AES-GCM with the DEK
3. **Key Encryption**: The DEK is encrypted using NHN Cloud SKM
4. **Storage**: Both encrypted data and encrypted DEK are stored together

### Key Rotation Support
- **Automatic Tracking**: Tracks key versions returned by NHN Cloud SKM API
- **Version Management**: Stores key version information for proper decryption
- **Seamless Rotation**: Supports key rotation without data migration

### Supported Mechanisms
- **Direct Encryption** (Legacy): For backward compatibility with existing encrypted data
- **Envelope Encryption** (Default): For new encryption operations, supports unlimited data size

## Configuration Examples

### Using Environment Variables
```bash
export NHN_CLOUD_SKM_APP_KEY="your-app-key"
export NHN_CLOUD_SKM_KEY_ID="your-key-id"
export NHN_CLOUD_SKM_USER_ACCESS_KEY_ID="your-access-key-id"
export NHN_CLOUD_SKM_USER_SECRET_ACCESS_KEY="your-secret-access-key"
export NHN_CLOUD_SKM_MAC_ADDRESS="your-mac-address"  # Optional
```

### Using Configuration Map
```go
wrapper := nhncloudskm.NewWrapper()
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "app_key":                "your-app-key",
    "key_id":                 "your-key-id", 
    "user_access_key_id":     "your-access-key-id",
    "user_secret_access_key": "your-secret-access-key",
    "endpoint":               "https://api-keymanager.nhncloudservice.com",
    "mac_address":            "your-mac-address",  // Optional
}))
```

### Using Wrapper Options
```go
wrapper := nhncloudskm.NewWrapper()
_, err := wrapper.SetConfig(ctx, 
    wrapping.WithKeyId("your-key-id"),
    nhncloudskm.WithAppKey("your-app-key"),
    nhncloudskm.WithUserAccessKeyID("your-access-key-id"),
    nhncloudskm.WithUserSecretAccessKey("your-secret-access-key"),
    nhncloudskm.WithEndpoint("https://api-keymanager.nhncloudservice.com"),
    nhncloudskm.WithMACAddress("your-mac-address"),  // Optional
)
```

## NHN Cloud SKM Requirements

- Valid NHN Cloud project with Secure Key Manager (SKM) service enabled
- Symmetric key created in NHN Cloud SKM console
- User account with SKM access permissions
- Authentication method configured (one or more):
  - IPv4 address authentication
  - MAC address authentication  
  - Client certificate authentication

## Security Considerations

### Authentication
- Uses NHN Cloud user credentials for API authentication
- Supports optional MAC address filtering for enhanced security

### Encryption Details
- **Data Encryption**: AES-256-GCM for actual data
- **Key Protection**: NHN Cloud SKM symmetric key encryption
- **Integrity**: Built-in integrity verification through AES-GCM

### Best Practices
- Rotate NHN Cloud user credentials regularly
- Use different keys for different environments (dev/staging/production)
- Configure appropriate authentication methods (IPv4/MAC/Certificate)
- Monitor key usage and access through NHN Cloud SKM console
- Use approval workflows for production key management

## Compatibility

### OpenBao Integration
This wrapper is designed for use with OpenBao auto-unseal functionality:

```hcl
seal "nhncloudskm" {
  app_key                = "your-app-key"
  key_id                 = "your-key-id"
  user_access_key_id     = "your-access-key-id"
  user_secret_access_key = "your-secret-access-key"
  endpoint               = "https://api-keymanager.nhncloudservice.com"
  mac_address            = "your-mac-address"  # Optional
}
```

### Backward Compatibility
- Supports decryption of data encrypted with direct encryption method
- New encryptions use envelope encryption by default
- Seamless migration path for existing encrypted data

## Error Handling

Common error scenarios and solutions:

| Error | Cause | Solution |
|-------|-------|----------|
| `app key is required` | Missing app key configuration | Set `NHN_CLOUD_SKM_APP_KEY` environment variable |
| `key ID is required` | Missing key ID configuration | Set `NHN_CLOUD_SKM_KEY_ID` environment variable |
| `user access key ID is required` | Missing access key | Set `NHN_CLOUD_SKM_USER_ACCESS_KEY_ID` environment variable |
| `user secret access key is required` | Missing secret key | Set `NHN_CLOUD_SKM_USER_SECRET_ACCESS_KEY` environment variable |
| `encryption API failed: invalid app key` | Invalid app key | Verify app key in NHN Cloud console |
| `key decryption failed` | Key access denied or invalid key ID | Check key permissions and key ID |

## Testing

### Unit Tests
```bash
go test ./...
```

### Acceptance Tests
Requires valid NHN Cloud SKM credentials:
```bash
export NHNCLOUD_SKM_ACCEPTANCE_TESTS=1
export NHN_CLOUD_SKM_APP_KEY="your-app-key"
export NHN_CLOUD_SKM_KEY_ID="your-key-id"
export NHN_CLOUD_SKM_USER_ACCESS_KEY_ID="your-access-key-id"
export NHN_CLOUD_SKM_USER_SECRET_ACCESS_KEY="your-secret-access-key"

go test ./... -v
```