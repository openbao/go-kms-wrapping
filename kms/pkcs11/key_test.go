// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"strings"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	s, p := session.TestSession(t)

	t.Run("Secret", func(t *testing.T) {
		t.Run("AES", func(t *testing.T) {
			obj, err := keybuilder.AES(32).Generate(s)
			require.NoError(t, err)

			sec, err := fromObject(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &secret{}, sec)
			require.Implements(t, (*kms.Key)(nil), sec)
			require.NotImplements(t, (*kms.AsymmetricKey)(nil), sec)
			require.NotImplements(t, (*kms.DigestSigner)(nil), sec)
			require.NotImplements(t, (*kms.DigestVerifier)(nil), sec)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.CipherFactory)(nil), sec)

			a := sec.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_AES)

			require.True(t, a.CanDecrypt)
			require.True(t, a.CanEncrypt)
			require.True(t, a.IsSensitive)

			require.False(t, a.CanSign)
			require.False(t, a.CanVerify)
			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(32*8))
			require.Equal(t, a.Curve, kms.Curve_None)
		})
	})

	t.Run("Pair", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			o1, o2, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			kp, err := pairFromObjects(s, p, o1, o2)
			require.NoError(t, err)

			require.IsType(t, &pair{}, kp)
			require.Implements(t, (*kms.Key)(nil), kp)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.AsymmetricKey)(nil), kp)
			// require.Implements(t, (*kms.CipherFactory)(nil), kp)
			// require.Implements(t, (*kms.SignerFactory)(nil), kp)
			// require.Implements(t, (*kms.VerifierFactory)(nil), kp)

			a := kp.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Private)

			// SoftHSM defaults all of these to true.
			require.True(t, a.CanSign)
			require.True(t, a.CanVerify)
			require.True(t, a.CanDecrypt)
			require.True(t, a.CanEncrypt)
			require.True(t, a.IsSensitive)

			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			for _, curve := range []kms.Curve{
				kms.Curve_P256, kms.Curve_P384, kms.Curve_P521,
			} {
				t.Run(strings.ToUpper(curve.String()), func(t *testing.T) {
					o1, o2, err := keybuilder.EC(curve).Generate(s)
					require.NoError(t, err)

					kp, err := pairFromObjects(s, p, o1, o2)
					require.NoError(t, err)

					require.IsType(t, &pair{}, kp)
					require.Implements(t, (*kms.Key)(nil), kp)
					require.NotImplements(t, (*kms.CipherFactory)(nil), kp)

					// TODO(satoqz): Implement these interfaces.
					// require.Implements(t, (*kms.AsymmetricKey)(nil), kp)
					// require.Implements(t, (*kms.SignerFactory)(nil), kp)
					// require.Implements(t, (*kms.VerifierFactory)(nil), kp)

					a := kp.GetKeyAttributes()

					require.Equal(t, a.KeyType, kms.KeyType_EC_Private)

					// SoftHSM defaults all these to true, even on EC keys.
					require.True(t, a.CanSign)
					require.True(t, a.CanVerify)
					require.True(t, a.CanDecrypt)
					require.True(t, a.CanEncrypt)
					require.True(t, a.IsSensitive)

					require.False(t, a.IsExportable)
					require.False(t, a.IsPersistent)

					require.Equal(t, a.Curve, curve)
					require.Equal(t, a.BitKeyLen, curve.Len())
				})
			}
		})
	})

	t.Run("Public", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			obj, _, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			pub, err := fromObject(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &public{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.NotImplements(t, (*kms.DigestSigner)(nil), pub)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			// require.Implements(t, (*kms.CipherFactory)(nil), pub)
			// require.Implements(t, (*kms.VerifierFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Public)

			require.True(t, a.CanVerify)
			require.True(t, a.CanEncrypt)

			require.False(t, a.CanSign)
			require.False(t, a.CanDecrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			obj, _, err := keybuilder.EC(kms.Curve_P256).Generate(s)
			require.NoError(t, err)

			pub, err := fromObject(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &public{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.NotImplements(t, (*kms.DigestVerifier)(nil), pub)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			// require.Implements(t, (*kms.CipherFactory)(nil), pub)
			// require.Implements(t, (*kms.VerifierFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_EC_Public)

			require.True(t, a.CanVerify)
			require.True(t, a.CanEncrypt)

			require.False(t, a.CanSign)
			require.False(t, a.CanDecrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.Curve, kms.Curve_P256)
			require.Equal(t, a.BitKeyLen, kms.Curve_P256.Len())
		})
	})

	t.Run("Private", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			_, obj, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			pub, err := fromObject(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &private{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.NotImplements(t, (*kms.DigestVerifier)(nil), pub)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			// require.Implements(t, (*kms.CipherFactory)(nil), pub)
			// require.Implements(t, (*kms.SignerFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Private)

			require.True(t, a.CanSign)
			require.True(t, a.CanDecrypt)
			require.True(t, a.IsSensitive)

			require.False(t, a.CanVerify)
			require.False(t, a.CanEncrypt)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			_, obj, err := keybuilder.EC(kms.Curve_P256).Generate(s)
			require.NoError(t, err)

			pub, err := fromObject(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &private{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.NotImplements(t, (*kms.DigestVerifier)(nil), pub)

			// TODO(satoqz): Implement these interfaces.
			// require.Implements(t, (*kms.CipherFactory)(nil), pub)
			// require.Implements(t, (*kms.SignerFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_EC_Private)

			require.True(t, a.CanSign)
			require.True(t, a.CanDecrypt)
			require.True(t, a.IsSensitive)

			require.False(t, a.CanVerify)
			require.False(t, a.CanEncrypt)
			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.Curve, kms.Curve_P256)
			require.Equal(t, a.BitKeyLen, kms.Curve_P256.Len())
		})
	})
}
