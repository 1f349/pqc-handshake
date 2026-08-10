// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"crypto/sha256"
	"crypto/sha512"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/mitm"
	"github.com/1f349/handshake/net/packets"
	pqc_crypto "github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

//TODO: All tests

var marshalLocalKey crypto.KemPrivateKey
var marshalRemoteKey crypto.KemPrivateKey
var verifyLocalKey crypto.SigPrivateKey
var verifyRemoteKey crypto.SigPrivateKey
var KeyCheckHash = sha256.New
var HMACBase = sha512.New
var SigVerifyHash = sha512.New

func GetVerifyLocalKey() crypto.SigPrivateKey {
	if verifyLocalKey == nil {
		scheme := pqc_crypto.WrapSig(mldsa44.Scheme())
		var err error
		_, verifyLocalKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return verifyLocalKey
}

func GetVerifyRemoteKey() crypto.SigPrivateKey {
	if verifyRemoteKey == nil {
		scheme := pqc_crypto.WrapSig(mldsa44.Scheme())
		var err error
		_, verifyRemoteKey, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
	}
	return verifyRemoteKey
}

func GetVoucher(kemKey crypto.KemPublicKey, sigKey crypto.SigPrivateKey, expireIn time.Duration) *config.SigConfig {
	kbts, err := kemKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	pkbts, err := sigKey.Public().MarshalBinary()
	if err != nil {
		panic(err)
	}
	d := crypto.NewSigData(kbts, time.Now(), time.Now().Add(expireIn), SigVerifyHash(), sigKey)
	if d == nil {
		panic("signature generation failed")
	}
	dbts, err := d.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return &config.SigConfig{
		Data: dbts,
		Key:  pkbts,
	}
}

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
		HMACHash:      HMACBase,
		KeyCheckHash:  KeyCheckHash,
		ValidDuration: time.Second * 5,
	}

	assert.NoError(t, remoteSettings.SetPrivateKey(GetMarshalRemoteKey()))

	localSettings := &config.NodeConfig{
		KEM:           GetMarshalLocalKey().Scheme(),
		HMACHash:      HMACBase,
		KeyCheckHash:  KeyCheckHash,
		ValidDuration: time.Second * 5,
		ConnID:        packets.GetUUID(),
	}

	assert.NoError(t, localSettings.SetPrivateKey(GetMarshalLocalKey()))

	remoteKemTable := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
	assert.NoError(t, remoteKemTable.Add(GetMarshalLocalKey().Public(), nil))

	localKemTable := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
	assert.NoError(t, localKemTable.Add(GetMarshalRemoteKey().Public(), nil))

	remoteSigTable := config.NewSigVerifierTableConfig(GetVerifyLocalKey().Scheme(), KeyCheckHash)
	assert.NoError(t, remoteSigTable.Add(GetVerifyLocalKey().Public()))

	localSigTable := config.NewSigVerifierTableConfig(GetVerifyRemoteKey().Scheme(), KeyCheckHash)
	assert.NoError(t, localSigTable.Add(GetVerifyRemoteKey().Public()))

	vouchLocalSigLocal := GetVoucher(GetMarshalLocalKey().Public(), GetVerifyLocalKey(), time.Hour*8)
	vouchLocalSigRemote := GetVoucher(GetMarshalLocalKey().Public(), GetVerifyRemoteKey(), time.Hour*8)
	vouchRemoteSigRemote := GetVoucher(GetMarshalRemoteKey().Public(), GetVerifyRemoteKey(), time.Hour*8)

	sigRunner := func(t *testing.T, remoteSigTable config.SigVerifierTableConfig, vouchLocalSigLocal *config.SigConfig) {
		t.Run("MainFlow", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2BLocal", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2BRemote", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2BRemoteKLocal", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := remoteKemTable.Clone()
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2BRemoteULocal", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2BLocalRemote", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, rset, lkt, rkt, vouchLocalSigLocal, nil, nil, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})

		t.Run("MainFlow2A", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2A2BLocal", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2A2BRemote", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2A2BRemoteKLocal", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := remoteKemTable.Clone()
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2A2BRemoteULocal", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
		t.Run("MainFlow2A2BLocalRemote", func(t *testing.T) {
			lkt := config.NewKemTableConfig(GetMarshalLocalKey().Scheme(), KeyCheckHash)
			rkt := config.NewKemTableConfig(GetMarshalRemoteKey().Scheme(), KeyCheckHash)
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, rset, lkt, rkt, vouchLocalSigLocal, vouchRemoteSigRemote, localSigTable, remoteSigTable, nil, nil)
			lkbts, err := GetMarshalLocalKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = rkt.Find(lkbts)
			assert.NoError(t, err)
			rkbts, err := GetMarshalRemoteKey().Public().MarshalBinary()
			assert.NoError(t, err)
			_, err = lkt.Find(rkbts)
			assert.NoError(t, err)
		})
	}

	t.Run("NoSig", func(t *testing.T) {
		t.Run("MainFlow", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), lkt, remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2BLocal", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, remoteSettings.Clone(), lkt, remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2BRemote", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, lkt, remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2BLocalRemote", func(t *testing.T) {
			lkt := localKemTable.Clone()
			assert.NoError(t, lkt.SetRemoteKey(remoteSettings.GetPrivateKey().Public(), localSettings.ConnID))
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, rset, lkt, remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})

		t.Run("MainFlow2A", func(t *testing.T) {
			testOneHandshake(t, localSettings.Clone(), remoteSettings.Clone(), localKemTable.Clone(), remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2A2BLocal", func(t *testing.T) {
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, remoteSettings.Clone(), localKemTable.Clone(), remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2A2BRemote", func(t *testing.T) {
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, localSettings.Clone(), rset, localKemTable.Clone(), remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
		t.Run("MainFlow2A2BLocalRemote", func(t *testing.T) {
			lset := localSettings.Clone()
			lset.RequestLocalPublicKey = true
			rset := remoteSettings.Clone()
			rset.RequestLocalPublicKey = true
			testOneHandshake(t, lset, rset, localKemTable.Clone(), remoteKemTable.Clone(), nil, nil, nil, nil, nil, nil)
		})
	})

	t.Run("Sig", func(t *testing.T) {
		sigRunner(t, remoteSigTable, vouchLocalSigLocal)
	})
	t.Run("USig", func(t *testing.T) {
		sigRunner(t, localSigTable, vouchLocalSigRemote)
	})
}

func testOneHandshake(t *testing.T, localSettings *config.NodeConfig, remoteSettings *config.NodeConfig,
	localKemTable config.KemTableConfig, remoteKemTable config.KemTableConfig, localPSig *config.SigConfig, remotePSig *config.SigConfig,
	localSigTable config.SigVerifierTableConfig, remoteSigTable config.SigVerifierTableConfig, expectFailErrorLocal error, expectFailErrorRemote error) {
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

	remoteHandshaker := net.NewRemoteHandshakerWithConfig(remoteMarshal, remoteSettings, remotePSig, remoteSigTable, SigVerifyHash, remoteKemTable)

	localHandshaker := net.NewLocalHandshakerWithConfig(localMarshal, localSettings, localPSig, localSigTable, SigVerifyHash, localKemTable)

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
