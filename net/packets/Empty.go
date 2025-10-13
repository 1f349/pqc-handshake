package packets

import (
	"io"
)

const ConnectionRejectedPacketType = PacketType(1)
const PublicKeyRequestPacketType = PacketType(5)
const SignatureRequestPacketType = PacketType(7)
const SignaturePublicKeyRequestPacketType = PacketType(9)

// EmptyPayload Provides a payload for ConnectionRejectedPacketType, PublicKeyRequestPacketType, SignatureRequestPacketType and SignaturePublicKeyRequestPacketType
type EmptyPayload struct {
}

func (e *EmptyPayload) WriteTo(w io.Writer) (n int64, err error) {
	return 0, nil
}

func (e *EmptyPayload) ReadFrom(r io.Reader) (n int64, err error) {
	return 0, nil
}

func (e *EmptyPayload) Size() uint {
	return 0
}
