// (C) 1f349 2026 - BSD-3-Clause License

package config

import (
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	pqc_crypto "github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
	"time"
)

func keyKemTest(t *testing.T, scheme crypto.KemScheme) (crypto.KemPublicKey, crypto.KemPrivateKey, []byte) {
	k, kp, err := scheme.GenerateKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, kp)
	assert.NotNil(t, k)
	kbts, err := k.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, kbts)
	return k, kp, kbts
}

func TestNodeConfig_Valid(t *testing.T) {
	scheme := pqc_crypto.WrapKem(mlkem768.Scheme())
	hashProv := func() hash.Hash { return sha256.New() }
	t.Run("False", func(t *testing.T) {
		assert.False(t, (&config.NodeConfig{}).Valid())

		assert.False(t, (&config.NodeConfig{KeyCheckHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme}).Valid())

		assert.False(t, (&config.NodeConfig{KEM: scheme, KeyCheckHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{KeyCheckHash: hashProv, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KeyCheckHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, KEMPrivateKeyData: make([]byte, 0)}).Valid())

		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv}).Valid())
		assert.False(t, (&config.NodeConfig{KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KeyCheckHash: hashProv, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, KeyCheckHash: hashProv, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())

		assert.False(t, (&config.NodeConfig{KEM: scheme, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0)}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{HMACHash: hashProv, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		assert.False(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv, ValidDuration: time.Millisecond}).Valid())
	})
	t.Run("True", func(t *testing.T) {
		assert.True(t, (&config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv, KEMPrivateKeyData: make([]byte, 0), ValidDuration: time.Millisecond}).Valid())
		_, kp, _ := keyKemTest(t, scheme)
		ncfg := &config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv, ValidDuration: time.Millisecond}
		assert.NoError(t, ncfg.SetPrivateKey(kp))
		assert.True(t, ncfg.Valid())
		assert.True(t, kp.Equals(ncfg.GetPrivateKey()))
	})
}

func TestNodeConfig_Key(t *testing.T) {
	scheme := pqc_crypto.WrapKem(mlkem768.Scheme())
	hashProv := sha256.New
	k, kp, kbts := keyKemTest(t, scheme)
	ncfg := &config.NodeConfig{KEM: scheme, HMACHash: hashProv, KeyCheckHash: hashProv, ValidDuration: time.Millisecond}
	t.Run("SetPrivateKey", func(t *testing.T) {
		assert.NoError(t, ncfg.SetPrivateKey(kp))
	})
	assert.True(t, ncfg.Valid())
	t.Run("GetPrivateKey", func(t *testing.T) {
		assert.True(t, kp.Equals(ncfg.GetPrivateKey()))
		assert.True(t, k.Equals(ncfg.GetPrivateKey().Public()))
	})
	t.Run("GetPublicKeyData", func(t *testing.T) {
		assert.Equal(t, kbts, ncfg.GetPublicKeyData())
	})
	t.Run("GetPublicKeyHash", func(t *testing.T) {
		assert.Equal(t, packets.BinaryMarshalHash(k, hashProv()), ncfg.GetPublicKeyHash(hashProv()))
	})
	t.Run("Clone", func(t *testing.T) {
		cncfg := ncfg.Clone()
		assert.True(t, cncfg.Valid())
		cncfg.ValidDuration = time.Second
		assert.NotEqual(t, cncfg.ValidDuration, ncfg.ValidDuration)
		assert.Equal(t, time.Millisecond, ncfg.ValidDuration)
		assert.Equal(t, time.Second, cncfg.ValidDuration)
		assert.True(t, kp.Equals(cncfg.GetPrivateKey()))
		assert.True(t, k.Equals(cncfg.GetPrivateKey().Public()))
		assert.True(t, ncfg.GetPrivateKey().Equals(ncfg.GetPrivateKey()))
		assert.True(t, ncfg.GetPrivateKey().Public().Equals(ncfg.GetPrivateKey().Public()))
	})
}
