// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package azurekeyvault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

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

type managedIdentityKind int

const (
	undefined managedIdentityKind = iota
	clientId
	resourceId
)

// Wrapper is an Wrapper that uses Azure Key Vault
// for crypto operations.  Azure Key Vault currently does not support
// keys that can encrypt long data (RSA keys).  Due to this fact, we generate
// and AES key and wrap the key using Key Vault and store it with the
// data
type Wrapper struct {
	tenantID      string
	clientID      string
	clientSecret  string
	vaultName     string
	keyName       string
	authMethod    authenticationMethod
	certPath      string
	certPass      string
	resourceID    string
	managedIdKind managedIdentityKind

	currentKeyId *atomic.Value

	environment    azure.Environment
	resource       string
	client         *azkeys.Client
	logger         hclog.Logger
	keyNotRequired bool
	baseURL        string
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

func mapAuthMethod(authMethod string) authenticationMethod {
	returnVal := Automatic
	authMethod = strings.ToLower(authMethod)

	switch authMethod {
	case "managed_identity":
		returnVal = ManagedIdentityCredential
	case "client_secret":
		returnVal = ClientSecretCredential
	case "workload_identity":
		returnVal = WorkloadIdentityCredential
	case "certificate":
		returnVal = CertificateCredential
	case "environment":
		returnVal = EnvironmentCredential
	case "default":
		returnVal = DefaultAzureCredential
	default:
		returnVal = Automatic
	}
	return returnVal
}

// SetConfig sets the fields on the Wrapper object based on
// values from the config parameter.
//
// Order of precedence:
// * Environment variable
// * Passed in config map
// * Managed Service Identity for instance
func (v *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	v.keyNotRequired = opts.withKeyNotRequired
	v.logger = opts.withLogger

	authMethod := ""
	switch {
	case os.Getenv(EnvVaultAzureKeyVaultAuthMethod) != "" && !opts.withDisallowEnvVars:
		authMethod = os.Getenv(EnvVaultAzureKeyVaultAuthMethod)
	case opts.withAuthMethod != "":
		authMethod = opts.withAuthMethod
	}

	v.authMethod = mapAuthMethod(authMethod)

	switch {
	case os.Getenv(EnvVaultAzureKeyVaultCertificatePath) != "" && !opts.withDisallowEnvVars:
		v.certPath = os.Getenv(EnvVaultAzureKeyVaultCertificatePath)
	case opts.withCertPath != "":
		v.certPath = opts.withCertPath
	}

	switch {
	case os.Getenv(EnvVaultAzureKeyVaultCertificatePassword) != "" && !opts.withDisallowEnvVars:
		v.certPass = os.Getenv(EnvVaultAzureKeyVaultCertificatePassword)
	case opts.withCertPass != "":
		v.certPass = opts.withCertPass
	}

	switch {
	case os.Getenv("AZURE_TENANT_ID") != "" && !opts.withDisallowEnvVars:
		v.tenantID = os.Getenv("AZURE_TENANT_ID")
	case opts.withTenantId != "":
		v.tenantID = opts.withTenantId
	}

	switch {
	case os.Getenv("AZURE_CLIENT_ID") != "" && !opts.withDisallowEnvVars:
		v.clientID = os.Getenv("AZURE_CLIENT_ID")
	case opts.withClientId != "":
		v.clientID = opts.withClientId
	}

	switch {
	case os.Getenv(EnvVaultAzureKeyVaultResourceId) != "" && !opts.withDisallowEnvVars:
		v.resourceID = os.Getenv(EnvVaultAzureKeyVaultResourceId)
	case opts.withResourceId != "":
		v.resourceID = opts.withResourceId
	}

	managedIdKind := ""
	switch {
	case os.Getenv(EnvVaultAzureKeyVaultManagedIdentityKind) != "" && !opts.withDisallowEnvVars:
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

	switch {
	case os.Getenv(EnvVaultAzureKeyVaultManagedIdentityKind) != "" && !opts.withDisallowEnvVars:

	}

	switch {
	case os.Getenv("AZURE_CLIENT_SECRET") != "" && !opts.withDisallowEnvVars:
		v.clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	case opts.withClientSecret != "":
		v.clientSecret = opts.withClientSecret
	}

	var envName string
	if !opts.withDisallowEnvVars {
		envName = os.Getenv("AZURE_ENVIRONMENT")
	}
	if envName == "" {
		envName = opts.withEnvironment
	}
	if envName == "" {
		v.environment = azure.PublicCloud
	} else {
		var err error
		v.environment, err = azure.EnvironmentFromName(envName)
		if err != nil {
			return nil, err
		}
	}

	var azResource string
	if !opts.withDisallowEnvVars {
		azResource = os.Getenv("AZURE_AD_RESOURCE")
	}
	if azResource == "" {
		azResource = opts.withResource
		if azResource == "" {
			azResource = v.environment.KeyVaultDNSSuffix
		}
	}
	v.environment.KeyVaultDNSSuffix = azResource
	v.resource = "https://" + azResource + "/"
	v.environment.KeyVaultEndpoint = v.resource

	switch {
	case os.Getenv(EnvAzureKeyVaultWrapperVaultName) != "" && !opts.withDisallowEnvVars:
		v.vaultName = os.Getenv(EnvAzureKeyVaultWrapperVaultName)
	case os.Getenv(EnvVaultAzureKeyVaultVaultName) != "" && !opts.withDisallowEnvVars:
		v.vaultName = os.Getenv(EnvVaultAzureKeyVaultVaultName)
	case opts.withVaultName != "":
		v.vaultName = opts.withVaultName
	default:
		return nil, errors.New("vault name is required")
	}

	switch {
	case os.Getenv(EnvAzureKeyVaultWrapperKeyName) != "" && !opts.withDisallowEnvVars:
		v.keyName = os.Getenv(EnvAzureKeyVaultWrapperKeyName)
	case os.Getenv(EnvVaultAzureKeyVaultKeyName) != "" && !opts.withDisallowEnvVars:
		v.keyName = os.Getenv(EnvVaultAzureKeyVaultKeyName)
	case opts.withKeyName != "":
		v.keyName = opts.withKeyName
	case v.keyNotRequired:
		// key not required to set config
	default:
		return nil, errors.New("key name is required")
	}

	// Set the base URL
	v.baseURL = v.buildBaseURL()

	if v.client == nil {
		client, err := v.getKeyVaultClient(nil)
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
			v.currentKeyId.Store(ParseKeyVersion(to.String((*string)(keyInfo.Key.KID))))
		}

		v.client = client
	}

	// Map that holds non-sensitive configuration info
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata["environment"] = v.environment.Name
	wrapConfig.Metadata["vault_name"] = v.vaultName
	wrapConfig.Metadata["key_name"] = v.keyName
	wrapConfig.Metadata["resource"] = v.resource

	return wrapConfig, nil
}

// Type returns the type for this particular Wrapper implementation
func (v *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypeAzureKeyVault, nil
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
		return nil, fmt.Errorf("error wrapping dat: %w", err)
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
	keyVersion := ParseKeyVersion(resp.KID.Version())
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

// Decrypt is used to decrypt the ciphertext
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

func (v *Wrapper) buildBaseURL() string {
	return fmt.Sprintf("https://%s.%s/", v.vaultName, v.environment.KeyVaultDNSSuffix)
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

func (v *Wrapper) getDefaultAzureCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant id is required for default azure credential authentication")
	}
	options := azidentity.DefaultAzureCredentialOptions{TenantID: v.tenantID}
	cred, err := azidentity.NewDefaultAzureCredential(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire default identity credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getEnvironmentCredential() (azcore.TokenCredential, error) {
	cred, err := azidentity.NewEnvironmentCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire environment credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getManagedIdentityCredential() (azcore.TokenCredential, error) {
	id := v.getManagedIdentityID()
	if id == nil || id.String() == "" {
		return nil, errors.New("either client or resource id is required for managed identity authentication")
	}
	cred, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{ID: id})
	if err != nil {
		return nil, fmt.Errorf("failed to get managed identity credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getClientSecretCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant id is required for azure client secret authentication")
	}
	cred, err := azidentity.NewClientSecretCredential(v.tenantID, v.clientID, v.clientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getCertificateCredential() (azcore.TokenCredential, error) {
	certData, err := os.ReadFile(v.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %v", v.certPath, err)
	}
	if v.clientID == "" {
		return nil, errors.New("client id is required for certificate authentication")
	}
	var password []byte
	if v.certPass != "" {
		password = []byte(v.certPass)
	}
	certs, key, err := azidentity.ParseCertificates(certData, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}
	if v.tenantID == "" {
		return nil, errors.New("tenant id is required for azure certificate authentication")
	}
	cred, err := azidentity.NewClientCertificateCredential(v.tenantID, v.clientID, certs, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get client certificate credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getWorkloadIdentityCredential() (azcore.TokenCredential, error) {
	if v.tenantID == "" {
		return nil, errors.New("tenant id is required for azure workload identity authentication")
	}
	options := azidentity.WorkloadIdentityCredentialOptions{TenantID: v.tenantID}
	cred, err := azidentity.NewWorkloadIdentityCredential(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to get workload identity credentials: %w", err)
	}
	return cred, nil
}

func (v *Wrapper) getCredential(method authenticationMethod) (azcore.TokenCredential, error) {
	switch method {
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

func (v *Wrapper) getAutomaticCredential() (azcore.TokenCredential, error) {
	switch v.authMethod {
	case Automatic:
		switch {
		case v.tenantID != "" && v.clientID != "" && v.clientSecret != "":
			return v.getCredential(ClientSecretCredential)
		case v.clientID != "":
			return v.getCredential(ManagedIdentityCredential)
		default:
			return v.getCredential(DefaultAzureCredential)
		}
	default:
		return v.getCredential(v.authMethod)
	}
}

func (v *Wrapper) getKeyVaultClient(withCertPool *x509.CertPool) (*azkeys.Client, error) {
	var err error
	var cred azcore.TokenCredential

	cred, err = v.getAutomaticCredential()
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
			RootCAs:       withCertPool,
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

// Kid gets returned as a full URL, get the last bit which is just
// the version
func ParseKeyVersion(kid string) string {
	keyVersionParts := strings.Split(kid, "/")
	return keyVersionParts[len(keyVersionParts)-1]
}
