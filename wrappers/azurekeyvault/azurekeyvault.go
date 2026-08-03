// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "azurekeyvault"

const (
	EnvAzureKeyVaultWrapperVaultName = "AZUREKEYVAULT_WRAPPER_VAULT_NAME"
	EnvVaultAzureKeyVaultVaultName   = "VAULT_AZUREKEYVAULT_VAULT_NAME"

	EnvAzureKeyVaultWrapperKeyName = "AZUREKEYVAULT_WRAPPER_KEY_NAME"
	EnvVaultAzureKeyVaultKeyName   = "VAULT_AZUREKEYVAULT_KEY_NAME"

	EnvVaultAzureKeyVaultAuthMethod          = "VAULT_AZUREKEYVAULT_AUTH_METHOD"
	EnvVaultAzureKeyVaultCertificatePath     = "VAULT_AZUREKEYVAULT_CERTIFICATE_PATH"
	EnvVaultAzureKeyVaultCertificatePassword = "VAULT_AZUREKEYVAULT_CERTIFICATE_PASSWORD"
	EnvVaultAzureKeyVaultManagedIdentityKind = "VAULT_AZUREKEYVAULT_MANAGED_IDENTITY_KIND"
	EnvVaultAzureKeyVaultResourceId          = "VAULT_AZUREKEYVAULT_RESOURCE_ID"
)

type authenticationMethod int

const (
	Automatic authenticationMethod = iota
	DefaultAzureCredential
	EnvironmentCredential
	ManagedIdentityCredential
	CertificateCredential
	ClientSecretCredential
	WorkloadIdentityCredential
)

// source: https://devblogs.microsoft.com/azure-sdk/guidance-for-applications-using-the-key-vault-libraries/
var envToKeyVaultMap = map[string]string{
	"azurecloud":        "vault.azure.net",
	"azurechinacloud":   "vault.azure.cn",
	"azureusgovernment": "vault.usgovcloudapi.net",
	"azuregermancloud":  "vault.microsoftazure.de",
}

type managedIdentityKind int

const (
	undefined managedIdentityKind = iota
	clientId
	resourceId
)

// Wrapper is an Wrapper that uses Azure Key Vault for crypto operations.
// Azure Key Vault currently does not support keys that can encrypt long
// data (RSA keys). Due to this fact, we generate AES key and wrap the
// key using Key Vault and store it with the data.
type Wrapper struct {
	tenantID      string
	clientID      string
	clientSecret  string
	keyName       string
	authMethod    authenticationMethod
	vaultName     string
	certPath      string
	certBytes     string
	certPassword  string
	resourceID    string
	managedIdKind managedIdentityKind

	keyNotRequired bool

	currentKeyId *atomic.Value
	client       *azkeys.Client

	environment string
	resource    string
	logger      hclog.Logger
	baseURL     string
}

// Ensure that we are implementing Wrapper
var _ wrapping.Wrapper = (*Wrapper)(nil)

// NewWrapper creates a new wrapper with the given options
func NewWrapper() *Wrapper {
	v := &Wrapper{
		currentKeyId: new(atomic.Value),
	}
	v.currentKeyId.Store("")
	return v
}

func (v *Wrapper) configureAuthMethod(authMethod string) {
	switch strings.ToLower(authMethod) {
	// Certificate and ClientSecret are the only two methods allowed
	// if `withDisallowEnvVars` flag is passed.
	case "certificate":
		v.authMethod = CertificateCredential
	case "client_secret":
		v.authMethod = ClientSecretCredential
	case "managed_identity":
		v.authMethod = ManagedIdentityCredential
	case "workload_identity":
		v.authMethod = WorkloadIdentityCredential
	case "environment":
		v.authMethod = EnvironmentCredential
	case "default":
		v.authMethod = DefaultAzureCredential
	default:
		switch {
		case v.tenantID != "" && v.clientID != "" && v.clientSecret != "":
			v.authMethod = ClientSecretCredential
		case v.certBytes != "" || v.certPath != "":
			v.authMethod = CertificateCredential
		case v.clientID != "":
			v.authMethod = ManagedIdentityCredential
		default:
			v.authMethod = DefaultAzureCredential
		}
	}
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence for Azure Key Vault values:
// * Environment variable (if WithDisallowEnvVars not provided)
// * Passed in config map
// * Managed Service Identity for instance
func (v *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	v.keyNotRequired = opts.withKeyNotRequired
	v.logger = opts.WithLogger

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultCertificatePath) != "":
		v.certPath = os.Getenv(EnvVaultAzureKeyVaultCertificatePath)
	case opts.withCertPath != "":
		v.certPath = opts.withCertPath
	}

	v.certBytes = opts.withCertBytes

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultCertificatePassword) != "":
		v.certPassword = os.Getenv(EnvVaultAzureKeyVaultCertificatePassword)
	case opts.withCertPassword != "":
		v.certPassword = opts.withCertPassword
	}

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv("AZURE_TENANT_ID") != "":
		v.tenantID = os.Getenv("AZURE_TENANT_ID")
	case opts.withTenantId != "":
		v.tenantID = opts.withTenantId
	}

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv("AZURE_CLIENT_ID") != "":
		v.clientID = os.Getenv("AZURE_CLIENT_ID")
	case opts.withClientId != "":
		v.clientID = opts.withClientId
	}

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv("AZURE_CLIENT_SECRET") != "":
		v.clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	case opts.withClientSecret != "":
		v.clientSecret = opts.withClientSecret
	}

	authMethod := ""
	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultAuthMethod) != "":
		authMethod = os.Getenv(EnvVaultAzureKeyVaultAuthMethod)
	case opts.withAuthMethod != "":
		authMethod = opts.withAuthMethod
	}

	v.configureAuthMethod(authMethod)
	if opts.WithDisallowEnvVars && !slices.Contains([]authenticationMethod{CertificateCredential, ClientSecretCredential}, v.authMethod) {
		return nil, fmt.Errorf("authentication method cannot be used in this context: %s", authMethod)
	}

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultResourceId) != "":
		v.resourceID = os.Getenv(EnvVaultAzureKeyVaultResourceId)
	case opts.withResourceId != "":
		v.resourceID = opts.withResourceId
	}

	managedIdKind := ""
	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultManagedIdentityKind) != "":
		managedIdKind = os.Getenv(EnvVaultAzureKeyVaultManagedIdentityKind)
	case opts.withManagedIdKind != "":
		managedIdKind = opts.withManagedIdKind
	}

	switch strings.ToUpper(managedIdKind) {
	case "CLIENT_ID":
		v.managedIdKind = clientId
	case "RESOURCE_ID":
		v.managedIdKind = resourceId
	default:
		v.managedIdKind = undefined
	}

	var envName string
	if !opts.WithDisallowEnvVars {
		envName = os.Getenv("AZURE_ENVIRONMENT")
	}
	if envName == "" {
		envName = opts.withEnvironment
	}
	if envName == "" {
		v.environment = "azurecloud"
	} else {
		envName = strings.ToLower(envName)
		_, ok := envToKeyVaultMap[envName]
		if !ok {
			return nil, fmt.Errorf("no cloud environment matching the name %q", envName)
		}

		v.environment = envName
	}

	var azResource string
	if !opts.WithDisallowEnvVars {
		azResource = os.Getenv("AZURE_AD_RESOURCE")
	}
	if azResource == "" {
		azResource = opts.withResource
		if azResource == "" {
			azResource = envToKeyVaultMap[v.environment]
		}
	}

	v.resource = fmt.Sprintf("https://%s/", azResource)

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvAzureKeyVaultWrapperVaultName) != "":
		v.vaultName = os.Getenv(EnvAzureKeyVaultWrapperVaultName)
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultVaultName) != "":
		v.vaultName = os.Getenv(EnvVaultAzureKeyVaultVaultName)
	case opts.withVaultName != "":
		v.vaultName = opts.withVaultName
	default:
		return nil, errors.New("vault name is required")
	}

	switch {
	case !opts.WithDisallowEnvVars && os.Getenv(EnvAzureKeyVaultWrapperKeyName) != "":
		v.keyName = os.Getenv(EnvAzureKeyVaultWrapperKeyName)
	case !opts.WithDisallowEnvVars && os.Getenv(EnvVaultAzureKeyVaultKeyName) != "":
		v.keyName = os.Getenv(EnvVaultAzureKeyVaultKeyName)
	case opts.withKeyName != "":
		v.keyName = opts.withKeyName
	case v.keyNotRequired:
		// key not required to set config
	default:
		return nil, errors.New("key name is required")
	}

	// Set the base URL
	v.baseURL = fmt.Sprintf("https://%s.%s/", v.vaultName, azResource)

	if v.client == nil {
		client, err := v.getKeyVaultClient()
		if err != nil {
			return nil, fmt.Errorf("error initializing Azure Key Vault wrapper client: %w", err)
		}

		if !v.keyNotRequired {
			// Test the client connection using provided key ID
			keyInfo, err := client.GetKey(ctx, v.keyName, "", nil)
			if err != nil {
				return nil, fmt.Errorf("error fetching Azure Key Vault wrapper key information: %w", err)
			}
			if keyInfo.Key == nil {
				return nil, errors.New("no key information returned")
			}
			v.currentKeyId.Store(keyInfo.Key.KID.Version())
		}

		v.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["environment"] = v.environment
	wrapConfig.Metadata["vault_name"] = v.vaultName
	wrapConfig.Metadata["key_name"] = v.keyName
	wrapConfig.Metadata["resource"] = v.resource

	return wrapConfig, nil
}

// Type returns the type for this particular Wrapper implementation
func (v *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

// KeyId returns the last known key id
func (v *Wrapper) KeyId(_ context.Context) (string, error) {
	return v.currentKeyId.Load().(string), nil
}

// Encrypt is used to encrypt using Azure Key Vault.
// This returns the ciphertext, and/or any errors from this
// call.
func (v *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}
	// Encrypt the DEK using Key Vault
	algo := azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
	params := azkeys.KeyOperationsParameters{
		Algorithm: &algo,
		Value:     env.Key,
	}
	// Wrap key with the latest version for the key name
	resp, err := v.client.WrapKey(ctx, v.keyName, "", params, nil)
	if err != nil {
		return nil, err
	}

	// Store the current key version
	keyVersion := resp.KID.Version()
	v.currentKeyId.Store(keyVersion)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      keyVersion,
			WrappedKey: resp.Result,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (v *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("given input for decryption is nil")
	}

	if in.KeyInfo == nil {
		return nil, errors.New("key info is nil")
	}

	// Unwrap the key
	wrappedBytes, err := base64.RawURLEncoding.DecodeString(string(in.KeyInfo.WrappedKey))
	if err != nil {
		// legacy unwrap as the key used to be stored base64 encoded and this is now handled in the json marshalling
		// if it fails, the key is not encoded and can be used directly
		wrappedBytes = in.KeyInfo.WrappedKey
	}
	algo := azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP256
	params := azkeys.KeyOperationsParameters{
		Algorithm: &algo,
		Value:     wrappedBytes,
	}

	resp, err := v.client.UnwrapKey(ctx, v.keyName, in.KeyInfo.KeyId, params, nil)
	if err != nil {
		return nil, err
	}

	envInfo := &wrapping.EnvelopeInfo{
		Key:        resp.Result,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}
	return wrapping.EnvelopeDecrypt(envInfo, opt...)
}

func (v *Wrapper) getManagedIdentityID() azidentity.ManagedIDKind {
	switch v.managedIdKind {
	case clientId, undefined:
		return azidentity.ClientID(v.clientID)
	case resourceId:
		return azidentity.ResourceID(v.resourceID)
	default:
		return azidentity.ManagedIDKind(nil)
	}
}

// getDefaultAzureCredential attempts to authenticate with each of these credential types, in the following order:
//   - [EnvironmentCredential]
//   - [WorkloadIdentityCredential]
//   - [ManagedIdentityCredential]
//   - [AzureCLICredential]
//   - [AzureDeveloperCLICredential]
//   - [AzurePowerShellCredential]
func (v *Wrapper) getDefaultAzureCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant_id is required for default azure credential authentication")
	}
	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{TenantID: v.tenantID})
	if err != nil {
		return nil, fmt.Errorf("failed to get default identity credentials: %w", err)
	}
	return cred, nil
}

// getEnvironmentCredential attempts to authenticate by reading environment variables.
func (v *Wrapper) getEnvironmentCredential() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewEnvironmentCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment credentials: %w", err)
	}
	return cred, nil
}

// getManagedIdentityCredential attempts to authenticate by an [Azure managed identity]
// in any hosting environment supporting managed identities, determined by the env vars.
func (v *Wrapper) getManagedIdentityCredential() (azcore.TokenCredential, error) {
	id := v.getManagedIdentityID()
	if id == nil || id.String() == "" {
		return nil, errors.New("either client_id or resource_id is required for managed identity authentication")
	}
	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: id})
	if err != nil {
		return nil, fmt.Errorf("failed to get managed identity credentials: %w", err)
	}
	return cred, nil
}

// getClientSecretCredential attempts to authenticate by providing static credentials.
func (v *Wrapper) getClientSecretCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant_id is required for azure client secret authentication")
	}

	// there's no validation of clientID in azure-sdk, but I'm pretty sure it's required.
	if v.clientID == "" {
		return nil, errors.New("client_id is required for azure client secret authentication")
	}

	cred, err := azidentity.NewClientSecretCredential(v.tenantID, v.clientID, v.clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret credentials: %w", err)
	}
	return cred, nil
}

// getCertificateCredential attempts to authenticate by providing certificate.
func (v *Wrapper) getCertificateCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant_id is required for azure certificate authentication")
	}

	// there's no validation of clientID in azure-sdk, but I'm pretty sure it's required.
	if v.clientID == "" {
		return nil, errors.New("client_id is required for certificate authentication")
	}

	var certData []byte
	var err error

	switch {
	case v.certPath == "" && v.certBytes == "":
		return nil, errors.New("either cert_path or cert_bytes are required for certificate authentication")
	case v.certPath != "":
		certData, err = os.ReadFile(v.certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate file %s: %v", v.certPath, err)
		}
	}

	if len(certData) < 1 {
		certData = []byte(v.certBytes)
	}

	if len(certData) < 1 {
		return nil, errors.New("missing required certificate contents")
	}

	var password []byte
	if v.certPassword != "" {
		password = []byte(v.certPassword)
	}

	certs, key, err := azidentity.ParseCertificates(certData, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	cred, err := azidentity.NewClientCertificateCredential(v.tenantID, v.clientID, certs, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client certificate credentials: %w", err)
	}
	return cred, nil
}

// getWorkloadIdentityCredential attempts to authenticate by using Azure workload identity on Kubernetes.
// Requires a TokenFilePath file containing a Kubernetes service account token, which is read from env vars.
func (v *Wrapper) getWorkloadIdentityCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant_id is required for azure workload identity authentication")
	}
	cred, err := azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{TenantID: v.tenantID})
	if err != nil {
		return nil, fmt.Errorf("failed to get workload identity credentials: %w", err)
	}
	return cred, nil
}

// getCredential routes to appropriate authentication method depending on the authMethod.
func (v *Wrapper) getCredential() (azcore.TokenCredential, error) {
	switch v.authMethod {
	case DefaultAzureCredential:
		return v.getDefaultAzureCredential()
	case EnvironmentCredential:
		return v.getEnvironmentCredential()
	case ManagedIdentityCredential:
		return v.getManagedIdentityCredential()
	case ClientSecretCredential:
		return v.getClientSecretCredential()
	case CertificateCredential:
		return v.getCertificateCredential()
	case WorkloadIdentityCredential:
		return v.getWorkloadIdentityCredential()
	default:
		return nil, fmt.Errorf("unknown authentication method")
	}
}

func (v *Wrapper) getKeyVaultClient() (*azkeys.Client, error) {
	cred, err := v.getCredential()
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	customTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
	}
	if http2Transport, err := http2.ConfigureTransports(customTransport); err == nil {
		// if the connection has been idle for 10 seconds, send a ping frame for a health check
		http2Transport.ReadIdleTimeout = 10 * time.Second
		// if there's no response to the ping within 2 seconds, close the connection
		http2Transport.PingTimeout = 2 * time.Second
	}

	clientOpts := &azkeys.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: &http.Client{Transport: customTransport}},
	}

	client, err := azkeys.NewClient(v.baseURL, cred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyvault client %w", err)
	}

	return client, nil
}

// Client returns the AzureKeyVault client used by the wrapper.
func (v *Wrapper) Client() *azkeys.Client {
	return v.client
}

// Logger returns the logger used by the wrapper.
func (v *Wrapper) Logger() hclog.Logger {
	return v.logger
}

// BaseURL returns the base URL for key management operation requests based
// on the Azure Vault name and environment.
func (v *Wrapper) BaseURL() string {
	return v.baseURL
}
