// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"github.com/1f349/handshake/net/packets"
	"github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validSignedPacketSigPublicKeyPayload *packets.SignedPacketSigPublicKeyPayload = nil
var invalidSignedPacketSigPublicKeyPayload *packets.SignedPacketSigPublicKeyPayload = nil

func GetValidSignedPacketSigPublicKeyPayload() *packets.SignedPacketSigPublicKeyPayload {
	if validSignedPacketSigPublicKeyPayload == nil {
		validSignedPacketSigPublicKeyPayload = &packets.SignedPacketSigPublicKeyPayload{}
		scheme := crypto.WrapSig(mldsa44.Scheme())
		k, _, err := scheme.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		err = validSignedPacketSigPublicKeyPayload.Save(k)
		if err != nil {
			panic(err)
		}
		return validSignedPacketSigPublicKeyPayload
	}
	return validSignedPacketSigPublicKeyPayload
}

func GetInvalidSignedPacketSigPublicKeyPayload() *packets.SignedPacketSigPublicKeyPayload {
	if invalidSignedPacketSigPublicKeyPayload != nil {
		return invalidSignedPacketSigPublicKeyPayload
	}
	invalidSignedPacketSigPublicKeyPayload = &packets.SignedPacketSigPublicKeyPayload{Data: []byte{0, 1, 2, 3}}
	return invalidSignedPacketSigPublicKeyPayload
}

func TestValidSignedPacketSigPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidSignedPacketSigPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &packets.SignedPacketSigPublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.WrapSig(mldsa44.Scheme()))
	assert.NoError(t, err)
	assert.NotNil(t, k)
	ko, err := payload.Load(nil)
	assert.NoError(t, err)
	assert.NotNil(t, ko)
	if k != nil && ko != nil {
		assert.True(t, ko.Equals(k))
	}
}

func TestInvalidSignedPacketSigPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidSignedPacketSigPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &packets.SignedPacketSigPublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.WrapSig(mldsa44.Scheme()))
	assert.Error(t, err)
	assert.Nil(t, k)
}
