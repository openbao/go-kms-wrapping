# AWS KMS Wrapper

This wrapper provides integration with [AWS Key Management Service (KMS)](https://aws.amazon.com/kms/) for encryption operations.

## Features

- Envelope encryption for large payloads (>4KB)
- Support for symmetric and asymmetric keys
- Additional Authenticated Data (AAD) support
- Automatic retry with exponential backoff
- Multi-region key support
- AWS IAM integration

## Configuration

### Configuration Parameters

| Parameter | Environment Variable | Description | Default | Required |
|-----------|---------------------|-------------|---------|----------|
| `kms_key_id` | `AWSKMS_WRAPPER_KEY_ID` | KMS key ID, ARN, alias, or multi-region key | - | Yes |
| `region` | `AWS_REGION` | AWS region | - | Yes* |
| `endpoint` | `AWS_ENDPOINT` | Custom endpoint (for LocalStack, etc.) | AWS default | No |
| `access_key` | `AWS_ACCESS_KEY_ID` | AWS access key ID | - | No** |
| `secret_key` | `AWS_SECRET_ACCESS_KEY` | AWS secret access key | - | No** |
| `session_token` | `AWS_SESSION_TOKEN` | AWS session token | - | No |
| `role_arn` | `AWSKMS_WRAPPER_ROLE_ARN` | IAM role to assume | - | No |
| `role_session_name` | `AWSKMS_WRAPPER_ROLE_SESSION_NAME` | Session name for assumed role | `go-kms-wrapping` | No |
| `shared_creds_file` | `AWS_SHARED_CREDENTIALS_FILE` | Path to credentials file | `~/.aws/credentials` | No |
| `shared_creds_profile` | `AWS_PROFILE` | Profile to use from credentials file | `default` | No |
| `web_identity_token_file` | `AWS_WEB_IDENTITY_TOKEN_FILE` | Path to web identity token | - | No |

\* Required unless using instance metadata or container credentials
\** Using IAM roles is strongly recommended over access keys

### Authentication Methods

The wrapper supports standard AWS authentication methods in the following order:

1. **Static Credentials**: Directly provided access key and secret
2. **Environment Variables**: Standard AWS environment variables
3. **Shared Credentials File**: AWS CLI credentials file
4. **EC2 Instance Role**: EC2 instance metadata service
5. **ECS Task Role**: ECS task credentials
6. **Web Identity**: Kubernetes service account tokens (EKS)
7. **SSO**: AWS SSO credentials

## Usage Examples

### Basic Usage with IAM Role

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
    
    // Create wrapper
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
    
    log.Printf("Decrypted: %s", decrypted)
}
```

### Using Key Alias

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "kms_key_id": "alias/my-application-key",
    "region":     "us-east-1",
}))
```

### Multi-Region Key

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123412341234123456789012",
    "region":     "eu-west-1", // Can use in any region
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

### Assume Role Configuration

```go
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "kms_key_id":         "alias/production-key",
    "region":             "us-east-1",
    "role_arn":           "arn:aws:iam::123456789012:role/KMSAccessRole",
    "role_session_name":  "my-app-session",
}))
```

## Testing

### Unit Tests

```bash
go test ./wrappers/awskms
```

### Integration Tests

Integration tests require AWS credentials and a KMS key:

```bash
export AWS_REGION=us-east-1
export AWSKMS_WRAPPER_KEY_ID=alias/test-key
go test ./wrappers/awskms -tags=integration
```

### Testing with LocalStack

For local development without AWS access:

```bash
# Start LocalStack
docker run -d \
  --name localstack \
  -p 4566:4566 \
  -e SERVICES=kms \
  localstack/localstack

# Create a test key
aws --endpoint-url=http://localhost:4566 \
    kms create-key \
    --region us-east-1

# Run tests
export AWS_ENDPOINT=http://localhost:4566
export AWS_REGION=us-east-1
export AWSKMS_WRAPPER_KEY_ID=<key-id-from-above>
go test ./wrappers/awskms
```

## Performance Considerations

### Connection Pooling

The AWS SDK automatically manages connection pooling. You can tune it via environment variables:

```bash
export AWS_MAX_ATTEMPTS=3
export AWS_MAX_CONNECTIONS=100
```

### Envelope Encryption

For payloads larger than 4KB, the wrapper automatically uses envelope encryption:

1. Generates a data encryption key (DEK) using KMS
2. Encrypts the plaintext with AES-GCM using the DEK
3. Encrypts the DEK with KMS
4. Returns both encrypted DEK and encrypted data

This reduces KMS API calls and improves performance for large data.

### Caching

Consider implementing caching for frequently accessed data:

```go
type CachedWrapper struct {
    *awskms.Wrapper
    cache map[string][]byte
    mu    sync.RWMutex
}

func (w *CachedWrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
    key := base64.StdEncoding.EncodeToString(blob.Ciphertext)
    
    w.mu.RLock()
    if plaintext, ok := w.cache[key]; ok {
        w.mu.RUnlock()
        return plaintext, nil
    }
    w.mu.RUnlock()
    
    plaintext, err := w.Wrapper.Decrypt(ctx, blob, opts...)
    if err != nil {
        return nil, err
    }
    
    w.mu.Lock()
    w.cache[key] = plaintext
    w.mu.Unlock()
    
    return plaintext, nil
}
```

## Security Best Practices

1. **Use IAM Roles**: Avoid hardcoding credentials
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "kms:Encrypt",
           "kms:Decrypt",
           "kms:GenerateDataKey"
         ],
         "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
       }
     ]
   }
   ```

2. **Enable Key Rotation**: AWS automatically rotates key material yearly

3. **Use Key Policies**: Restrict key usage to specific principals
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "Enable IAM User Permissions",
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::123456789012:root"
         },
         "Action": "kms:*",
         "Resource": "*"
       },
       {
         "Sid": "Allow use of the key for encryption",
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::123456789012:role/ApplicationRole"
         },
         "Action": [
           "kms:Encrypt",
           "kms:Decrypt",
           "kms:GenerateDataKey"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

4. **Audit with CloudTrail**: Monitor all KMS operations

5. **Use VPC Endpoints**: Keep traffic within AWS network
   ```go
   _, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
       "kms_key_id": "alias/my-key",
       "region":     "us-east-1",
       "endpoint":   "https://kms-vpc-endpoint.us-east-1.vpce.amazonaws.com",
   }))
   ```

## Troubleshooting

### Common Errors

1. **AccessDeniedException**
   - Check IAM permissions
   - Verify key policy allows your principal
   - Ensure key is in the correct region

2. **InvalidKeyId.NotFound**
   - Verify key ID/ARN is correct
   - Check region configuration
   - Ensure key exists and is enabled

3. **ThrottlingException**
   - Implement exponential backoff
   - Consider using envelope encryption
   - Check AWS service limits

### Debug Logging

Enable AWS SDK debug logging:

```go
import "github.com/aws/aws-sdk-go/aws"

// In your configuration
awsConfig := aws.NewConfig().WithLogLevel(aws.LogDebugWithHTTPBody)
```

Or via environment variable:
```bash
export AWS_SDK_LOG_LEVEL=debug
```

## Additional Resources

- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [AWS SDK for Go](https://aws.github.io/aws-sdk-go-v2/)
- [OpenBao Auto-Unseal with AWS KMS](https://openbao.org/docs/configuration/seal/awskms)