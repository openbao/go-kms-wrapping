# Contributing to Go-KMS-Wrapping

Thank you for your interest in contributing to Go-KMS-Wrapping! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Adding a New Provider](#adding-a-new-provider)

## Code of Conduct

This project follows the [OpenBao Code of Conduct](https://github.com/openbao/openbao/blob/main/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Git
- Make
- Docker (for testing some providers)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/go-kms-wrapping.git
   cd go-kms-wrapping
   ```

3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/openbao/go-kms-wrapping.git
   ```

### Development Environment

```bash
# Install dependencies
go mod download

# Install development tools
make tools

# Run tests
make test

# Run linters
make lint
```

## Development Process

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Write clean, idiomatic Go code
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Commit Your Changes

We use conventional commits for clear commit history:

```bash
# Types: feat, fix, docs, style, refactor, test, chore
git commit -s -m "feat: add support for new KMS provider"
```

**Important**: All commits must be signed off (`-s` flag) to comply with the Developer Certificate of Origin (DCO).

## Coding Standards

### Go Code Style

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting
- Use meaningful variable and function names
- Keep functions small and focused
- Document exported types and functions

### Error Handling

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to encrypt with KMS: %w", err)
}

// Bad: Just returning the error
if err != nil {
    return err
}
```

### Interface Design

```go
// Keep interfaces small and focused
type Encryptor interface {
    Encrypt(ctx context.Context, plaintext []byte) (*BlobInfo, error)
}

// Not
type KMSOperations interface {
    Encrypt(...)
    Decrypt(...)
    Sign(...)
    Verify(...)
    // Too many methods
}
```

## Testing

### Unit Tests

```go
func TestWrapper_Encrypt(t *testing.T) {
    ctx := context.Background()
    wrapper := NewWrapper()
    
    // Arrange
    plaintext := []byte("test data")
    
    // Act
    encrypted, err := wrapper.Encrypt(ctx, plaintext)
    
    // Assert
    require.NoError(t, err)
    require.NotNil(t, encrypted)
    require.NotEqual(t, plaintext, encrypted.Ciphertext)
}
```

### Integration Tests

Integration tests require actual KMS services:

```bash
# Run integration tests for AWS KMS
INTEG_TEST=true AWS_REGION=us-east-1 go test ./wrappers/awskms -v

# Using LocalStack for AWS
docker run -d -p 4566:4566 localstack/localstack
AWS_ENDPOINT=http://localhost:4566 make test-aws
```

### Test Coverage

We aim for >80% test coverage:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Documentation

### Code Documentation

```go
// Wrapper provides envelope encryption using AWS KMS.
// It implements the wrapping.Wrapper interface and automatically
// handles large payloads through envelope encryption.
type Wrapper struct {
    client   kmsiface.KMSAPI
    keyID    string
    aad      []byte
}

// Encrypt encrypts the provided plaintext using AWS KMS.
// If the plaintext is larger than 4KB, envelope encryption is used.
//
// The returned BlobInfo contains the ciphertext and metadata needed
// for decryption.
func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opts ...wrapping.Option) (*wrapping.BlobInfo, error) {
    // Implementation
}
```

### README Documentation

When adding features or providers:
- Update the main README.md
- Add provider-specific README in `wrappers/PROVIDER/`
- Include configuration examples
- Document environment variables
- Add troubleshooting tips

## Submitting Changes

### Pull Request Process

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests and linters**:
   ```bash
   make test
   make lint
   ```

3. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request**:
   - Use a clear, descriptive title
   - Reference any related issues
   - Describe what changed and why
   - Include test results

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass (if applicable)
- [ ] New tests added

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Commits are signed-off (DCO)
```

## Adding a New Provider

### 1. Create Provider Package

```bash
mkdir -p wrappers/myprovider
cd wrappers/myprovider
```

### 2. Implement the Wrapper Interface

```go
package myprovider

import (
    "context"
    "github.com/openbao/go-kms-wrapping/v2"
)

type Wrapper struct {
    client   MyProviderClient
    keyID    string
}

func NewWrapper() *Wrapper {
    return &Wrapper{}
}

func (w *Wrapper) SetConfig(ctx context.Context, opts ...wrapping.Option) (*wrapping.WrapperConfig, error) {
    // Implementation
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opts ...wrapping.Option) (*wrapping.BlobInfo, error) {
    // Implementation
}

func (w *Wrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
    // Implementation
}
```

### 3. Add Tests

```go
func TestWrapper_Lifecycle(t *testing.T) {
    // Test configuration
    // Test encryption
    // Test decryption
    // Test key rotation
}
```

### 4. Add Documentation

Create `wrappers/myprovider/README.md`:

```markdown
# MyProvider KMS Wrapper

## Configuration

| Parameter | Environment Variable | Description | Required |
|-----------|---------------------|-------------|----------|
| key_id | MYPROVIDER_KEY_ID | The key identifier | Yes |
| region | MYPROVIDER_REGION | Provider region | No |

## Example Usage

\```go
wrapper := myprovider.NewWrapper()
_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
    "key_id": "my-key-id",
    "region": "us-east-1",
}))
\```

## Testing

\```bash
MYPROVIDER_KEY_ID=test-key go test ./wrappers/myprovider
\```
```

### 5. Update Main Documentation

- Add provider to the supported providers table in README.md
- Update any relevant examples
- Add to the provider configuration section

## Questions?

If you have questions, please:

1. Check existing [issues](https://github.com/openbao/go-kms-wrapping/issues)
2. Join the [OpenBao community chat](https://chat.lfx.linuxfoundation.org)
3. Ask on the [mailing list](https://lists.openssf.org/g/openbao)

Thank you for contributing to Go-KMS-Wrapping!