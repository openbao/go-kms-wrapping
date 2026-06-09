// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package openstackbarbican

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/config"
	"github.com/gophercloud/gophercloud/v2/openstack/config/clouds"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/secrets"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const Type wrapping.WrapperType = "openstackbarbican"

const (
	contentTypeOctetStream = "application/octet-stream"
	defaultRetryAttempts   = 3
)

type secretType string

const (
	secretTypeSymmetric secretType = "symmetric"
)

var secretIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Wrapper struct {
	secretID     string
	currentKeyId *atomic.Value
	aead         cipher.AEAD

	newClient func(context.Context, *options) (barbicanClient, error)
	sleep     func(context.Context, int) error
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

func NewWrapper() *Wrapper {
	w := &Wrapper{
		currentKeyId: new(atomic.Value),
		newClient:    newGophercloudBarbicanClient,
		sleep:        sleepWithBackoff,
	}
	w.currentKeyId.Store("")
	return w
}

func (w *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	secretID, err := normalizeSecretRef(opts.withSecretRef)
	if err != nil {
		return nil, err
	}
	if opts.withEndpoint != "" {
		endpoint, err := normalizeEndpoint(opts.withEndpoint)
		if err != nil {
			return nil, fmt.Errorf("openstackbarbican: parse endpoint: %w", err)
		}
		opts.withEndpoint = endpoint
	}

	client, err := w.newClient(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: authenticate: %w", err)
	}

	secret, payload, err := w.fetchInitialKey(ctx, client, secretID)
	if err != nil {
		return nil, err
	}
	if err := validateSecret(secret, payload); err != nil {
		return nil, err
	}

	aesCipher, err := aes.NewCipher(payload)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: validate payload: %w", err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: validate payload: %w", err)
	}

	w.secretID = secretID
	w.aead = aead
	w.currentKeyId.Store(makeKeyID(secretID, client.Identity()))

	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = map[string]string{
		configSecretID: secretID,
		"key_id":       w.currentKeyId.Load().(string),
	}
	if opts.withEndpoint != "" {
		wrapConfig.Metadata[configEndpoint] = opts.withEndpoint
	}
	if opts.withRegion != "" {
		wrapConfig.Metadata[configRegion] = opts.withRegion
	}
	return wrapConfig, nil
}

func (w *Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return Type, nil
}

func (w *Wrapper) KeyId(context.Context) (string, error) {
	return w.currentKeyId.Load().(string), nil
}

func (w *Wrapper) Encrypt(_ context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("openstackbarbican: encrypt: plaintext is nil")
	}
	if w.aead == nil {
		return nil, errors.New("openstackbarbican: encrypt: wrapper is not configured")
	}
	opts, err := wrapping.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: encrypt: %w", err)
	}

	ciphertext := w.aead.Seal(nil, nil, plaintext, opts.WithAad)
	nonceSize := w.aead.NonceSize()
	return &wrapping.BlobInfo{
		Iv:         ciphertext[:nonceSize],
		Ciphertext: ciphertext[nonceSize:],
		KeyInfo: &wrapping.KeyInfo{
			KeyId: w.currentKeyId.Load().(string),
		},
	}, nil
}

func (w *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in == nil {
		return nil, errors.New("openstackbarbican: decrypt: ciphertext is nil")
	}
	if w.aead == nil {
		return nil, errors.New("openstackbarbican: decrypt: wrapper is not configured")
	}
	if in.KeyInfo == nil || in.KeyInfo.KeyId == "" {
		return nil, errors.New("openstackbarbican: decrypt: missing key id")
	}
	keyID := w.currentKeyId.Load().(string)
	if in.KeyInfo.KeyId != keyID {
		return nil, fmt.Errorf("openstackbarbican: decrypt: unknown key id %q", in.KeyInfo.KeyId)
	}
	opts, err := wrapping.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: decrypt: %w", err)
	}

	ciphertext := append(in.Iv, in.Ciphertext...)
	plaintext, err := w.aead.Open(nil, nil, ciphertext, opts.WithAad)
	if err != nil {
		return nil, fmt.Errorf("openstackbarbican: decrypt: %w", err)
	}
	return plaintext, nil
}

func (w *Wrapper) Init(context.Context, ...wrapping.Option) error {
	return nil
}

func (w *Wrapper) Finalize(context.Context, ...wrapping.Option) error {
	w.aead = nil
	return nil
}

func (w *Wrapper) fetchInitialKey(ctx context.Context, client barbicanClient, secretID string) (*barbicanSecret, []byte, error) {
	var secret *barbicanSecret
	var payload []byte
	var err error
	for attempt := 1; attempt <= defaultRetryAttempts; attempt++ {
		secret, err = client.GetSecret(ctx, secretID)
		if err == nil {
			payload, err = client.GetPayload(ctx, secretID, contentTypeOctetStream)
		}
		if err == nil {
			return secret, payload, nil
		}
		if !isTransient(err) || attempt == defaultRetryAttempts {
			return nil, nil, wrapFetchError(err)
		}
		if sleepErr := w.sleep(ctx, attempt); sleepErr != nil {
			return nil, nil, fmt.Errorf("openstackbarbican: fetch payload: %w", sleepErr)
		}
	}
	return nil, nil, fmt.Errorf("openstackbarbican: fetch payload: %w", err)
}

func validateSecret(secret *barbicanSecret, payload []byte) error {
	if secret == nil {
		return errors.New("openstackbarbican: fetch metadata: missing secret metadata")
	}
	if secret.SecretType != string(secretTypeSymmetric) {
		return fmt.Errorf("openstackbarbican: validate metadata: unsupported secret type %q", secret.SecretType)
	}
	contentType := secret.ContentTypes["default"]
	if contentType == "" {
		return errors.New("openstackbarbican: validate metadata: missing payload content type")
	}
	if contentType != contentTypeOctetStream {
		return fmt.Errorf("openstackbarbican: validate metadata: unsupported payload content type %q", contentType)
	}
	if len(payload) != 32 {
		return fmt.Errorf("openstackbarbican: validate payload: expected 32 bytes, got %d", len(payload))
	}
	return nil
}

func normalizeSecretRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("openstackbarbican: parse secret_ref: missing secret_ref")
	}
	if secretIDPattern.MatchString(ref) {
		return strings.ToLower(ref), nil
	}

	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("openstackbarbican: parse secret_ref: invalid secret_ref %q", ref)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i, part := range parts {
		if part == "secrets" && i+1 < len(parts) {
			secretID := parts[i+1]
			if secretIDPattern.MatchString(secretID) {
				if len(parts) == i+2 || (len(parts) == i+3 && parts[i+2] == "payload") {
					return strings.ToLower(secretID), nil
				}
				return "", fmt.Errorf("openstackbarbican: parse secret_ref: unsupported secret_ref path %q", u.Path)
			}
		}
	}
	return "", fmt.Errorf("openstackbarbican: parse secret_ref: unsupported secret_ref path %q", u.Path)
}

func normalizeEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid endpoint %q", endpoint)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("endpoint must use https, got %q", u.Scheme)
	}
	return strings.TrimRight(endpoint, "/"), nil
}

func makeKeyID(secretID string, identity string) string {
	digest := sha256.Sum256([]byte(strings.TrimRight(identity, "/") + "/" + secretID))
	return secretID + ":" + hex.EncodeToString(digest[:])[:16]
}

func wrapFetchError(err error) error {
	switch {
	case err == nil:
		return nil
	case isStatus(err, http.StatusUnauthorized), isStatus(err, http.StatusForbidden), isStatus(err, http.StatusNotFound):
		return fmt.Errorf("openstackbarbican: fetch metadata: %w", err)
	default:
		return fmt.Errorf("openstackbarbican: fetch payload: %w", err)
	}
}

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	var status interface{ GetStatusCode() int }
	if errors.As(err, &status) {
		code := status.GetStatusCode()
		return code == http.StatusTooManyRequests || code >= 500
	}
	var netErr interface{ Timeout() bool }
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isStatus(err error, status int) bool {
	var statusErr interface{ GetStatusCode() int }
	if errors.As(err, &statusErr) {
		return statusErr.GetStatusCode() == status
	}
	return false
}

func sleepWithBackoff(ctx context.Context, attempt int) error {
	delay := time.Duration(250*(1<<(attempt-1))) * time.Millisecond
	if delay > 2*time.Second {
		delay = 2 * time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type barbicanSecret struct {
	SecretType   string
	ContentTypes map[string]string
}

type barbicanClient interface {
	GetSecret(context.Context, string) (*barbicanSecret, error)
	GetPayload(context.Context, string, string) ([]byte, error)
	Identity() string
}

type gophercloudBarbicanClient struct {
	client   *gophercloud.ServiceClient
	identity string
}

func newGophercloudBarbicanClient(ctx context.Context, opts *options) (barbicanClient, error) {
	httpClient := http.Client{Timeout: 30 * time.Second}

	var provider *gophercloud.ProviderClient
	var endpointOpts gophercloud.EndpointOpts
	var err error
	if !opts.Options.WithDisallowEnvVars && os.Getenv("OS_CLOUD") != "" {
		parseOpts := []clouds.ParseOption{}
		if opts.withRegion != "" {
			parseOpts = append(parseOpts, clouds.WithRegion(opts.withRegion))
		}
		authOpts, eo, tlsConfig, err := clouds.Parse(parseOpts...)
		if err != nil {
			return nil, err
		}
		authOpts.AllowReauth = true
		endpointOpts = eo
		provider, err = config.NewProviderClient(ctx, authOpts, config.WithHTTPClient(httpClient), config.WithTLSConfig(tlsConfig))
		if err != nil {
			return nil, err
		}
	} else if !opts.Options.WithDisallowEnvVars {
		authOpts, err := openstack.AuthOptionsFromEnv()
		if err != nil {
			return nil, err
		}
		authOpts.AllowReauth = true
		endpointOpts = gophercloud.EndpointOpts{Region: opts.withRegion}
		provider, err = config.NewProviderClient(ctx, authOpts, config.WithHTTPClient(httpClient))
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("openstackbarbican: env vars disallowed and no alternative auth configured")
	}

	serviceClient, err := openstack.NewKeyManagerV1(provider, endpointOpts)
	if err != nil {
		return nil, err
	}
	if opts.withEndpoint != "" {
		serviceClient.Endpoint = strings.TrimRight(opts.withEndpoint, "/") + "/"
		serviceClient.ResourceBase = serviceClient.Endpoint
		if !strings.HasSuffix(serviceClient.ResourceBase, "/v1/") {
			serviceClient.ResourceBase = strings.TrimRight(serviceClient.ResourceBase, "/") + "/v1/"
		}
	}
	if _, err := normalizeEndpoint(serviceClient.ResourceBase); err != nil {
		return nil, fmt.Errorf("openstackbarbican: parse endpoint: %w", err)
	}

	return &gophercloudBarbicanClient{
		client:   serviceClient,
		identity: strings.TrimRight(serviceClient.ResourceBase, "/"),
	}, nil
}

func (c *gophercloudBarbicanClient) GetSecret(ctx context.Context, id string) (*barbicanSecret, error) {
	secret, err := secrets.Get(ctx, c.client, id).Extract()
	if err != nil {
		return nil, err
	}
	return &barbicanSecret{
		SecretType:   secret.SecretType,
		ContentTypes: secret.ContentTypes,
	}, nil
}

func (c *gophercloudBarbicanClient) GetPayload(ctx context.Context, id string, contentType string) ([]byte, error) {
	return secrets.GetPayload(ctx, c.client, id, secrets.GetPayloadOpts{
		PayloadContentType: contentType,
	}).Extract()
}

func (c *gophercloudBarbicanClient) Identity() string {
	return c.identity
}
