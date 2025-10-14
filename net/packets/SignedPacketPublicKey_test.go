package packets

import (
	"bytes"
	"github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"testing"
)

var validSignedPacketPublicKeyPayload = &SignedPacketPublicKeyPayload{}
var invalidSignedPacketPublicKeyPayload = &SignedPacketPublicKeyPayload{}

func GetValidSignedPacketPublicKeyPayload() *SignedPacketPublicKeyPayload {
	if validSignedPacketPublicKeyPayload == nil {
		return validSignedPacketPublicKeyPayload
	}
	scheme := crypto.WrapSig(mldsa44.Scheme())
	k, _, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	err = validSignedPacketPublicKeyPayload.Save(k)
	if err != nil {
		panic(err)
	}
	return validSignedPacketPublicKeyPayload
}

func GetInvalidSignedPacketPublicKeyPayload() *SignedPacketPublicKeyPayload {
	if invalidSignedPacketPublicKeyPayload == nil {
		return invalidSignedPacketPublicKeyPayload
	}
	invalidSignedPacketPublicKeyPayload = &SignedPacketPublicKeyPayload{Data: []byte{0, 1, 2, 3}}
	return invalidSignedPacketPublicKeyPayload
}

func TestValidSignedPacketPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetValidSignedPacketPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &SignedPacketPublicKeyPayload{}
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

func TestInvalidSignedPacketPublicKeyPayload(t *testing.T) {
	buff := new(bytes.Buffer)
	payload := GetInvalidSignedPacketPublicKeyPayload()
	n, err := payload.WriteTo(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	rPayload := &SignedPacketPublicKeyPayload{}
	n, err = rPayload.ReadFrom(buff)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, n, int64(0))
	assert.Equal(t, payload.Size(), uint(n))
	k, err := rPayload.Load(crypto.WrapSig(mldsa44.Scheme()))
	assert.Error(t, err)
	assert.Nil(t, k)
}
