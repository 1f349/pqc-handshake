// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net/packets"
	pqc_crypto "github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"slices"
	"testing"
	"time"
)

var validPublicKeySignedPacketPayload *packets.PublicKeySignedPacketPayload = nil
var validPublicKeySignedPacketPayloadKemPubKey crypto.KemPublicKey = nil
var validPublicKeySignedPacketPayloadSigPubKeyHash []byte = nil
var validPublicKeySignedPacketPayloadSigPubKey crypto.SigPublicKey = nil
var invalidPublicKeySignedPacketPayload *packets.PublicKeySignedPacketPayload = nil

func GetValidPublicKeySignedPacketPayload() *packets.PublicKeySignedPacketPayload {
	if validPublicKeySignedPacketPayload == nil {
		shash := sha256.New()
		scheme := pqc_crypto.WrapKem(mlkem768.Scheme())
		var err error
		validPublicKeySignedPacketPayloadKemPubKey, _, err = scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		kbts, err := validPublicKeySignedPacketPayloadKemPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		sigScheme := pqc_crypto.WrapSig(mldsa44.Scheme())
		var pk crypto.SigPrivateKey
		validPublicKeySignedPacketPayloadSigPubKey, pk, err = sigScheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		skbts, err := validPublicKeySignedPacketPayloadSigPubKey.MarshalBinary()
		if err != nil {
			panic(err)
		}
		sigData := crypto.NewSigData(kbts, time.Now(), time.Now().Add(time.Hour), shash, pk)
		shash.Reset()
		shash.Write(skbts)
		validPublicKeySignedPacketPayloadSigPubKeyHash = shash.Sum(nil)
		validPublicKeySignedPacketPayload = &packets.PublicKeySignedPacketPayload{SigPubKeyHash: validPublicKeySignedPacketPayloadSigPubKeyHash}
		err = validPublicKeySignedPacketPayload.Save(sigData)
		if err != nil {
			panic(err)
		}
	}
	return validPublicKeySignedPacketPayload
}

func GetInvalidPublicKeySignedPacketPayload() *packets.PublicKeySignedPacketPayload {
	if invalidPublicKeySignedPacketPayload != nil {
		return invalidPublicKeySignedPacketPayload
	}
	invalidPublicKeySignedPacketPayload = &packets.PublicKeySignedPacketPayload{SigPubKeyHash: []byte{0, 1, 2, 3}}
	return invalidPublicKeySignedPacketPayload
}

func TestValidPublicKeySignedPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidPublicKeySignedPacketPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &packets.PublicKeySignedPacketPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	assert.True(t, slices.Equal(validPublicKeySignedPacketPayloadSigPubKeyHash, rPayload.SigPubKeyHash))
	sigData, err := rPayload.Load(validPublicKeySignedPacketPayloadKemPubKey)
	assert.NoError(t, err)
	assert.NotNil(t, sigData.Signature)
	if sigData.Signature != nil {
		assert.True(t, sigData.Verify(sha256.New(), validPublicKeySignedPacketPayloadSigPubKey))
	}
}

func TestInvalidPublicKeySignedPacketPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidPublicKeySignedPacketPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &packets.PublicKeySignedPacketPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	sigData, err := rPayload.Load(validPublicKeySignedPacketPayloadKemPubKey)
	assert.True(t, slices.Equal([]byte{0, 1, 2, 3}, rPayload.SigPubKeyHash))
	assert.Error(t, err)
	assert.Nil(t, sigData.Signature)
}
