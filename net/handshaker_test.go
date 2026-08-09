// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/mitm"
	"github.com/1f349/handshake/net/packets"
	pqc_crypto "github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

//TODO: All tests

var marshalLocalKey crypto.KemPrivateKey
var marshalRemoteKey crypto.KemPrivateKey
var MarshalHMACBase = sha256.New

func GetMarshalLocalKey() crypto.KemPrivateKey {
	if marshalLocalKey == nil {
		scheme := pqc_crypto.WrapKem(mlkem768.Scheme())
		var err error
		_, marshalLocalKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return marshalLocalKey
}

func GetMarshalRemoteKey() crypto.KemPrivateKey {
	if marshalRemoteKey == nil {
		scheme := pqc_crypto.WrapKem(mlkem768.Scheme())
		var err error
		_, marshalRemoteKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return marshalRemoteKey
}

func TestHandshake(t *testing.T) {

	remoteSettings := &config.NodeConfig{
		KEM:           GetMarshalRemoteKey().Scheme(),
		HMACHash:      MarshalHMACBase,
		KeyCheckHash:  MarshalHMACBase,
		ValidDuration: time.Second * 5,
	}

	assert.NoError(t, remoteSettings.SetPrivateKey(GetMarshalRemoteKey()))

	localSettings := &config.NodeConfig{
		KEM:           GetMarshalLocalKey().Scheme(),
		HMACHash:      MarshalHMACBase,
		KeyCheckHash:  MarshalHMACBase,
		ValidDuration: time.Second * 5,
		ConnID:        packets.GetUUID(),
	}

	assert.NoError(t, localSettings.SetPrivateKey(GetMarshalLocalKey()))

	remoteKemTable := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), MarshalHMACBase)
	assert.NoError(t, remoteKemTable.Add(GetMarshalLocalKey().Public(), nil))

	localKemTable := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), MarshalHMACBase)
	assert.NoError(t, localKemTable.Add(GetMarshalRemoteKey().Public(), nil))

	t.Run("MainFlow", func(t *testing.T) {
		lkt := localKemTable.Clone()
		assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
		testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2BLocal", func(t *testing.T) {
		lkt := localKemTable.Clone()
		assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
		lset := localSettings.Clone()
		lset.RequestLocalPublicKey = true
		testOneHandshake(t, lset, remoteSettings.Clone(), lkt, remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2BRemote", func(t *testing.T) {
		lkt := localKemTable.Clone()
		assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
		rset := remoteSettings.Clone()
		rset.RequestLocalPublicKey = true
		testOneHandshake(t, localSettings.Clone(), rset, lkt, remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2BLocalRemote", func(t *testing.T) {
		lkt := localKemTable.Clone()
		assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
		lset := localSettings.Clone()
		lset.RequestLocalPublicKey = true
		rset := remoteSettings.Clone()
		rset.RequestLocalPublicKey = true
		testOneHandshake(t, lset, rset, lkt, remoteKemTable.Clone(), nil, nil)
	})

	t.Run("MainFlow2A", func(t *testing.T) {
		testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), localKemTable.Clone(), remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2A2BLocal", func(t *testing.T) {
		lset := localSettings.Clone()
		lset.RequestLocalPublicKey = true
		testOneHandshake(t, lset, remoteSettings.Clone(), localKemTable.Clone(), remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2A2BRemote", func(t *testing.T) {
		rset := remoteSettings.Clone()
		rset.RequestLocalPublicKey = true
		testOneHandshake(t, localSettings.Clone(), rset, localKemTable.Clone(), remoteKemTable.Clone(), nil, nil)
	})
	t.Run("MainFlow2A2BLocalRemote", func(t *testing.T) {
		lset := localSettings.Clone()
		lset.RequestLocalPublicKey = true
		rset := remoteSettings.Clone()
		rset.RequestLocalPublicKey = true
		testOneHandshake(t, lset, rset, localKemTable.Clone(), remoteKemTable.Clone(), nil, nil)
	})
}

func testOneHandshake(t *testing.T, localSettings *config.NodeConfig, remoteSettings *config.NodeConfig,
	localKemTable config.KemTableConfig, remoteKemTable config.KemTableConfig, expectFailErrorLocal error, expectFailErrorRemote error) {
	const buffSize = 1024 * 1024

	local := mitm.NewStream(1024, nil, nil)
	remote := mitm.NewStream(1024, nil, nil)

	remoteTransport := mitm.NewStreamableTransport(mitm.NewStreamOf(local.GetReadStream(), remote.GetWriteStream(), nil, nil), buffSize)
	localTransport := mitm.NewStreamableTransport(mitm.NewStreamOf(remote.GetReadStream(), local.GetWriteStream(), nil, nil), buffSize)

	remoteMarshal := &packets.HandshakePacketMarshaller{
		Conn: remoteTransport,
	}
	localMarshal := &packets.HandshakePacketMarshaller{
		Conn: localTransport,
	}

	remoteHandshaker := net.NewRemoteHandshakerWithConfig(remoteMarshal, remoteSettings, nil, nil, nil, remoteKemTable)

	localHandshaker := net.NewLocalHandshakerWithConfig(localMarshal, localSettings, nil, nil, nil, localKemTable)

	go func() {
		if expectFailErrorLocal == nil {
			assert.NoError(t, localHandshaker.Handshake())
			assert.False(t, localHandshaker.Handshaking())
			assert.False(t, localHandshaker.HandshakeFailed())
			assert.True(t, localHandshaker.HandshakeCompleted())
		} else {
			le := localHandshaker.Handshake()
			assert.Error(t, le)
			assert.Equal(t, expectFailErrorLocal, le)
			assert.False(t, localHandshaker.Handshaking())
			assert.True(t, localHandshaker.HandshakeFailed())
			assert.False(t, localHandshaker.HandshakeCompleted())
		}
	}()
	go func() {
		if expectFailErrorRemote == nil {
			assert.NoError(t, remoteHandshaker.Handshake())
			assert.False(t, remoteHandshaker.Handshaking())
			assert.False(t, remoteHandshaker.HandshakeFailed())
			assert.True(t, remoteHandshaker.HandshakeCompleted())
		} else {
			le := remoteHandshaker.Handshake()
			assert.Error(t, le)
			assert.Equal(t, expectFailErrorRemote, le)
			assert.False(t, remoteHandshaker.Handshaking())
			assert.True(t, remoteHandshaker.HandshakeFailed())
			assert.False(t, remoteHandshaker.HandshakeCompleted())
		}
	}()
	localHandshaker.WaitForHandshakeCompletion()
	remoteHandshaker.WaitForHandshakeCompletion()

	t.Log(localHandshaker.GetLocalSecret())
	t.Log(remoteHandshaker.GetLocalSecret())
	if expectFailErrorLocal == nil && expectFailErrorRemote == nil {
		assert.True(t, slices.Equal(localHandshaker.GetLocalSecret(), remoteHandshaker.GetLocalSecret()))
	}
	t.Log(localHandshaker.GetRemoteSecret())
	t.Log(remoteHandshaker.GetRemoteSecret())
	if expectFailErrorLocal == nil && expectFailErrorRemote == nil {
		assert.True(t, slices.Equal(localHandshaker.GetRemoteSecret(), remoteHandshaker.GetRemoteSecret()))
	}
	assert.NoError(t, localTransport.Close())
	assert.NoError(t, remoteTransport.Close())
}
