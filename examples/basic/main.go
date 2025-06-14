// Package main demonstrates basic usage of the go-kms-wrapping library
// with different KMS providers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/wrappers/aead"
	"github.com/openbao/go-kms-wrapping/v2/wrappers/awskms"
	"github.com/openbao/go-kms-wrapping/v2/wrappers/azurekeyvault"
	"github.com/openbao/go-kms-wrapping/v2/wrappers/gcpckms"
)

func main() {
	var (
		provider  = flag.String("provider", "aead", "KMS provider (aead, awskms, azurekeyvault, gcpckms)")
		plaintext = flag.String("plaintext", "Hello, World!", "Text to encrypt")
		aadData   = flag.String("aad", "", "Additional authenticated data")
	)
	flag.Parse()

	ctx := context.Background()

	// Create wrapper based on provider
	wrapper, err := createWrapper(*provider)
	if err != nil {
		log.Fatalf("Failed to create wrapper: %v", err)
	}

	// Configure the wrapper
	err = configureWrapper(ctx, wrapper, *provider)
	if err != nil {
		log.Fatalf("Failed to configure wrapper: %v", err)
	}

	// Prepare options
	var opts []wrapping.Option
	if *aadData != "" {
		opts = append(opts, wrapping.WithAad([]byte(*aadData)))
	}

	// Encrypt
	fmt.Printf("Encrypting: %s\n", *plaintext)
	encrypted, err := wrapper.Encrypt(ctx, []byte(*plaintext), opts...)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted data (%d bytes)\n", len(encrypted.Ciphertext))
	fmt.Printf("Key ID: %s\n", encrypted.KeyInfo.KeyId)

	// Decrypt
	decrypted, err := wrapper.Decrypt(ctx, encrypted, opts...)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(decrypted) != *plaintext {
		log.Fatalf("Decrypted text doesn't match original!")
	}

	fmt.Println("✅ Encryption/decryption successful!")
}

func createWrapper(provider string) (wrapping.Wrapper, error) {
	switch provider {
	case "aead":
		return aead.NewWrapper(), nil
	case "awskms":
		return awskms.NewWrapper(), nil
	case "azurekeyvault":
		return azurekeyvault.NewWrapper(), nil
	case "gcpckms":
		return gcpckms.NewWrapper(), nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func configureWrapper(ctx context.Context, wrapper wrapping.Wrapper, provider string) error {
	switch provider {
	case "aead":
		// For demo purposes, use a fixed key
		// In production, use a proper key derivation method
		key := make([]byte, 32) // 256-bit key
		copy(key, []byte("example-key-for-demo-purposes!"))

		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"key_id": "demo-key",
		}), aead.WithKey(key))
		return err

	case "awskms":
		keyID := os.Getenv("AWS_KMS_KEY_ID")
		if keyID == "" {
			return fmt.Errorf("AWS_KMS_KEY_ID environment variable is required")
		}

		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}

		config := map[string]string{
			"kms_key_id": keyID,
			"region":     region,
		}

		// Optional: use LocalStack for local testing
		if endpoint := os.Getenv("AWS_ENDPOINT"); endpoint != "" {
			config["endpoint"] = endpoint
		}

		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
		return err

	case "azurekeyvault":
		vaultName := os.Getenv("AZURE_KEY_VAULT_NAME")
		keyName := os.Getenv("AZURE_KEY_NAME")

		if vaultName == "" || keyName == "" {
			return fmt.Errorf("AZURE_KEY_VAULT_NAME and AZURE_KEY_NAME environment variables are required")
		}

		config := map[string]string{
			"vault_name": vaultName,
			"key_name":   keyName,
		}

		// Add service principal credentials if provided
		if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
			config["tenant_id"] = tenantID
		}
		if clientID := os.Getenv("AZURE_CLIENT_ID"); clientID != "" {
			config["client_id"] = clientID
		}
		if clientSecret := os.Getenv("AZURE_CLIENT_SECRET"); clientSecret != "" {
			config["client_secret"] = clientSecret
		}

		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
		return err

	case "gcpckms":
		keyRing := os.Getenv("GCP_KMS_KEY_RING")
		cryptoKey := os.Getenv("GCP_KMS_CRYPTO_KEY")

		if keyRing == "" || cryptoKey == "" {
			return fmt.Errorf("GCP_KMS_KEY_RING and GCP_KMS_CRYPTO_KEY environment variables are required")
		}

		config := map[string]string{
			"key_ring":   keyRing,
			"crypto_key": cryptoKey,
		}

		// Optional: specify credentials file
		if credsFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credsFile != "" {
			config["credentials"] = credsFile
		}

		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(config))
		return err

	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}
}