package packets

import (
	intbyteutils "github.com/1f349/int-byte-utils"
	"github.com/1f349/pqc-handshake/crypto"
	"io"
)

const SignedPacketPublicKeyPacketType = PacketType(10)

type SignedPacketPublicKeyPayload struct {
	Data []byte
	key  crypto.SigPublicKey
}

func (p *SignedPacketPublicKeyPayload) WriteTo(w io.Writer) (n int64, err error) {
	m, err := writeBuff(w, p.Data)
	return int64(m), err
}

func (p *SignedPacketPublicKeyPayload) ReadFrom(r io.Reader) (n int64, err error) {
	var m int
	m, err, p.Data = readBuff(r)
	return int64(m), err
}

func (p *SignedPacketPublicKeyPayload) Size() uint {
	return uint(intbyteutils.LenUintAsBytes(uint(len(p.Data))) + len(p.Data))
}

func (p *SignedPacketPublicKeyPayload) Load(scheme crypto.SigScheme) (crypto.SigPublicKey, error) {
	if p.key != nil {
		return p.key, nil
	}
	var err error
	p.key, err = scheme.UnmarshalBinaryPublicKey(p.Data)
	return p.key, err
}

func (p *SignedPacketPublicKeyPayload) Save(key crypto.SigPublicKey) error {
	if key == nil {
		return crypto.KeyNil
	}
	p.key = key
	var err error
	p.Data, err = key.MarshalBinary()
	return err
}
