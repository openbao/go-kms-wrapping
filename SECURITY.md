# Security Policy

## Reporting Security Vulnerabilities

We take the security of Go-KMS-Wrapping seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email**: [openbao-security@lists.openssf.org](mailto:openbao-security@lists.openssf.org)

**Please do NOT**:
- File a public GitHub issue for security vulnerabilities
- Discuss the vulnerability in public forums
- Share details on social media

### What to Include

When reporting a security vulnerability, please provide:

1. **Description**: A clear description of the vulnerability
2. **Impact**: How the vulnerability could be exploited
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions are affected
5. **Proof of Concept**: If applicable, include a minimal PoC
6. **Contact Information**: How we can reach you for follow-up

### Response Process

1. **Acknowledgment**: We'll acknowledge receipt within 48 hours
2. **Investigation**: We'll investigate and assess the vulnerability
3. **Fix Development**: We'll develop and test a fix
4. **Disclosure**: We'll coordinate disclosure with the reporter
5. **Release**: We'll release the fix and security advisory

## Security Best Practices

### For Users

#### Key Management
- **Separate Keys by Environment**: Use different keys for dev/staging/prod
- **Implement Key Rotation**: Regularly rotate encryption keys
- **Never Delete Keys**: Keys may be needed to decrypt historical data
- **Use Key Aliases**: Avoid hardcoding key IDs in code

#### Access Control
- **Principle of Least Privilege**: Grant minimum required permissions
- **Use IAM Roles**: Avoid hardcoding credentials
- **Enable Audit Logging**: Monitor all KMS operations
- **Regular Access Reviews**: Periodically review and revoke unnecessary access

#### Network Security
- **Use VPC Endpoints**: Keep traffic within cloud provider networks
- **Enable TLS**: Ensure all communications are encrypted in transit
- **Network Segmentation**: Isolate KMS traffic where possible

#### Error Handling
- **Don't Log Secrets**: Never log plaintext data or keys
- **Implement Proper Retry Logic**: Handle transient failures gracefully
- **Fail Securely**: Ensure failures don't expose sensitive data

### For Developers

#### Code Security
```go
// Good: Use context with timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Good: Handle errors properly
if err != nil {
    return fmt.Errorf("encryption failed: %w", err)
}

// Bad: Ignoring errors
encrypted, _ := wrapper.Encrypt(ctx, data)
```

#### Testing
```go
// Good: Use test fixtures, not real data
testData := []byte("test-plaintext-data")

// Bad: Using production data in tests
testData := []byte(os.Getenv("PROD_SECRET"))
```

#### Dependency Management
- **Pin Dependencies**: Use specific versions in go.mod
- **Regular Updates**: Keep dependencies updated for security patches
- **Vulnerability Scanning**: Use tools like `govulncheck`

## Common Security Issues

### 1. Key Leakage
**Risk**: Exposing encryption keys in logs, source code, or error messages

**Prevention**:
```go
// Good: Don't log the key
log.Printf("Using key ID: %s", keyID)

// Bad: Logging actual key material
log.Printf("Using key: %x", keyBytes)
```

### 2. Insufficient Error Handling
**Risk**: Error messages revealing sensitive information

**Prevention**:
```go
// Good: Generic error message
return errors.New("encryption operation failed")

// Bad: Exposing internal details
return fmt.Errorf("failed to encrypt with key %s: %v", keyID, err)
```

### 3. Replay Attacks
**Risk**: Reusing encrypted data without proper validation

**Prevention**:
```go
// Use AAD to bind encrypted data to context
aad := []byte(fmt.Sprintf("user:%s:timestamp:%d", userID, timestamp))
encrypted, err := wrapper.Encrypt(ctx, data, wrapping.WithAad(aad))
```

### 4. Side-Channel Attacks
**Risk**: Timing attacks revealing information about keys or data

**Prevention**:
- Use constant-time operations for key comparisons
- Implement consistent error handling timing
- Use hardware security modules when available

### 5. Credential Exposure
**Risk**: Hardcoded or exposed API credentials

**Prevention**:
```go
// Good: Use environment variables or IAM roles
keyID := os.Getenv("KMS_KEY_ID")

// Bad: Hardcoded credentials
keyID := "arn:aws:kms:us-east-1:123456789012:key/..."
```

## Security Checklist

### Before Production

- [ ] Keys are properly configured with access policies
- [ ] Using IAM roles/managed identities instead of access keys
- [ ] Audit logging enabled for all KMS operations
- [ ] Implementing key rotation strategy
- [ ] Not storing encrypted data alongside plaintext
- [ ] Using AAD where appropriate
- [ ] Monitoring for anomalous encryption/decryption patterns
- [ ] Error handling doesn't leak sensitive information
- [ ] Dependencies are up to date
- [ ] Security testing completed

### Provider-Specific Security

#### AWS KMS
- [ ] Key policies restrict access to authorized principals
- [ ] CloudTrail logging enabled
- [ ] VPC endpoints configured
- [ ] Automatic key rotation enabled
- [ ] Cross-region replication considered

#### Azure Key Vault
- [ ] Access policies follow least privilege
- [ ] Soft delete enabled
- [ ] Private endpoints configured
- [ ] Diagnostic logging enabled
- [ ] Purge protection enabled for critical keys

#### Google Cloud KMS
- [ ] IAM policies properly configured
- [ ] Audit logs enabled
- [ ] Private Google Access configured
- [ ] Automatic key rotation enabled
- [ ] HSM usage for sensitive workloads

## Vulnerability Disclosure Timeline

We follow responsible disclosure practices:

1. **Day 0**: Vulnerability reported
2. **Day 1-2**: Acknowledgment sent to reporter
3. **Day 3-7**: Initial assessment and impact analysis
4. **Day 8-30**: Fix development and testing
5. **Day 31-60**: Coordinated disclosure preparation
6. **Day 61**: Public disclosure (or earlier if actively exploited)

## Security Updates

We release security updates as soon as possible after a fix is available:

- **Critical**: Within 24-48 hours
- **High**: Within 1 week
- **Medium**: With next regular release
- **Low**: With next regular release

Subscribe to our [mailing list](https://lists.openssf.org/g/openbao) for security announcements.

## Additional Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [Cloud Security Alliance - Key Management](https://cloudsecurityalliance.org/guidance/csaguide.v3.0.pdf)

## Contact

For general security questions (non-vulnerabilities):
- [Mailing List](https://lists.openssf.org/g/openbao)
- [Community Chat](https://chat.lfx.linuxfoundation.org)