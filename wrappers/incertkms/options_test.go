package incertkms

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithKmsUrl", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// default is the public UAT endpoint
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsUrl = "https://kms-uat.incert.lu/kms"
		assert.Equal(opts, testOpts)

		const with = "http://localhost:3000"
		opts, err = getOpts(WithKmsUrl(with))
		require.NoError(err)
		testOpts.withKmsUrl = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKmsUsername", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of ""
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsUsername = ""
		assert.Equal(opts, testOpts)

		const with = "opo"
		opts, err = getOpts(WithKmsUsername(with))
		require.NoError(err)
		testOpts.withKmsUsername = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKmsPassword", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of ""
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsPassword = ""
		assert.Equal(opts, testOpts)

		const with = "Parizer1!"
		opts, err = getOpts(WithKmsPassword(with))
		require.NoError(err)
		testOpts.withKmsPassword = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKmsVSlot", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of ""
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsVSlot = ""
		assert.Equal(opts, testOpts)

		const with = "a73b7303-ce75-4666-8a3d-e9fb269424fb"
		opts, err = getOpts(WithKmsVSlot(with))
		require.NoError(err)
		testOpts.withKmsVSlot = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKmsKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of ""
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsKey = ""
		assert.Equal(opts, testOpts)

		const with = "bd5d7c4b-8ed3-4390-bcee-f37446bb420f"
		opts, err = getOpts(WithKmsKey(with))
		require.NoError(err)
		testOpts.withKmsKey = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithKmsKeyName", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of ""
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKmsKeyName = ""
		assert.Equal(opts, testOpts)

		const with = "openbao-seal-key"
		opts, err = getOpts(WithKmsKeyName(with))
		require.NoError(err)
		testOpts.withKmsKeyName = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithConfigMap", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		configMap := map[string]string{
			"kms_url":      "http://localhost:3000",
			"kms_username": "opo",
			"kms_password": "Parizer1!",
			"kms_vslot":    "a73b7303-ce75-4666-8a3d-e9fb269424fb",
			"kms_key":      "bd5d7c4b-8ed3-4390-bcee-f37446bb420f",
			"kms_key_name": "openbao-seal-key",
		}

		opts, err := getOpts(wrapping.WithConfigMap(configMap))
		require.NoError(err)
		assert.Equal("http://localhost:3000", opts.withKmsUrl)
		assert.Equal("opo", opts.withKmsUsername)
		assert.Equal("Parizer1!", opts.withKmsPassword)
		assert.Equal("a73b7303-ce75-4666-8a3d-e9fb269424fb", opts.withKmsVSlot)
		assert.Equal("bd5d7c4b-8ed3-4390-bcee-f37446bb420f", opts.withKmsKey)
		assert.Equal("openbao-seal-key", opts.withKmsKeyName)
	})
}
