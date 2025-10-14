package packets

import (
	"errors"
	intbyteutils "github.com/1f349/int-byte-utils"
	"github.com/1f349/pqc-handshake/crypto"
	"io"
)

const PublicKeySignedPacketType = PacketType(8)

var SigNil = errors.New("sig nil")

type PublicKeySignedPacketPayload struct {
	SignatureData []byte
	SigPubKeyHash []byte
	signature     *crypto.SigData
}

func (p *PublicKeySignedPacketPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, p.SignatureData)
	if err != nil {
		return int64(m), err
	}
	l, err := writeBuff(w, p.SigPubKeyHash)
	return int64(m + l), err
}

func (p *PublicKeySignedPacketPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, p.SignatureData = readBuff(r)
	if err != nil {
		return int64(m), err
	}
	var l int
	l, err, p.SigPubKeyHash = readBuff(r)
	return int64(m + l), err
}

func (p *PublicKeySignedPacketPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(p.SignatureData))) + len(p.SignatureData) + intbyteutils.LenUintAsBytes(uint(len(p.SigPubKeyHash))) + len(p.SigPubKeyHash))
}

func (p *PublicKeySignedPacketPayload) Load(kemKeyToCheck crypto.KemPublicKey) (*crypto.SigData, error) {
	if kemKeyToCheck == nil {
		return nil, crypto.KeyNil
	}
	bts, err := kemKeyToCheck.MarshalBinary()
	if err != nil {
		return nil, err
	}
	p.signature, err = crypto.UnmarshalSigData(p.SignatureData, bts)
	return p.signature, err
}

func (p *PublicKeySignedPacketPayload) Save(sigData *crypto.SigData) (err error) {
	if sigData == nil {
		return SigNil
	}
	p.SignatureData, err = sigData.MarshalBinary()
	return
}
