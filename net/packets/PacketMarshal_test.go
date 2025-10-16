// (C) 1f349 2025 - BSD-3-Clause License

package packets

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/1f349/handshake/net/packets"
	"github.com/1f349/pqc-handshake/crypto"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/stretchr/testify/assert"
	"io"
	"slices"
	"testing"
	"time"
)

func TestPacketMarshal(t *testing.T) {
	sharedPacketMarshalTest(t, new(bytes.Buffer), 0)
}

func TestPacketMarshalFragmented(t *testing.T) {
	const MTU = 1280
	sharedPacketMarshalTest(t, newMTUTransport(MTU), MTU)
}

func TestPacketMarshalFragmentedSmallMTU(t *testing.T) {
	//const MTU = HeaderSizeForFragmentation + 1 //Not, this may be the minimum valid, but the maximum number of fragments is 255
	const MTU = 64
	sharedPacketMarshalTest(t, newMTUTransport(MTU), MTU)
}

func sharedPacketMarshalTest(t *testing.T, transport io.ReadWriter, mtu uint) {
	marshal := &packets.PacketMarshaller{
		Conn: transport,
		MTU:  mtu,
	}
	connection := packets.GetUUID()
	pt := packets.MilliTime(time.Now())
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.ConnectionRejectedPacketType, ConnectionUUID: connection, Time: pt}, &packets.EmptyPayload{}, emptyPayloadChecker)
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.PublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, &packets.EmptyPayload{}, emptyPayloadChecker)
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.SignatureRequestPacketType, ConnectionUUID: connection, Time: pt}, &packets.EmptyPayload{}, emptyPayloadChecker)
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.SignaturePublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, &packets.EmptyPayload{}, emptyPayloadChecker)
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.PublicKeyDataPacketType, ConnectionUUID: connection, Time: pt}, GetValidPublicKeyPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		k, err := r.(*packets.PublicKeyPayload).Load(crypto.WrapKem(mlkem768.Scheme()))
		if err != nil || k == nil {
			return false
		}
		ko, err := o.(*packets.PublicKeyPayload).Load(nil)
		if err != nil || ko == nil {
			return false
		}
		return ko.Equals(k)
	})
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.PublicKeyDataPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidPublicKeyPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		k, err := r.(*packets.PublicKeyPayload).Load(crypto.WrapKem(mlkem768.Scheme()))
		if err != nil && k == nil {
			return true
		}
		return false
	})
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.SignedPacketSigPublicKeyPacketType, ConnectionUUID: connection, Time: pt}, GetValidSignedPacketSigPublicKeyPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		k, err := r.(*packets.SignedPacketSigPublicKeyPayload).Load(crypto.WrapSig(mldsa44.Scheme()))
		if err != nil || k == nil {
			return false
		}
		ko, err := o.(*packets.SignedPacketSigPublicKeyPayload).Load(nil)
		if err != nil || ko == nil {
			return false
		}
		return ko.Equals(k)
	})
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.SignedPacketSigPublicKeyPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidSignedPacketSigPublicKeyPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		k, err := r.(*packets.SignedPacketSigPublicKeyPayload).Load(crypto.WrapSig(mldsa44.Scheme()))
		if err != nil && k == nil {
			return true
		}
		return false
	})
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.PublicKeySignedPacketType, ConnectionUUID: connection, Time: pt}, GetValidPublicKeySignedPacketPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		if !slices.Equal(validPublicKeySignedPacketPayloadSigPubKeyHash, r.(*packets.PublicKeySignedPacketPayload).SigPubKeyHash) {
			return false
		}
		sigData, err := r.(*packets.PublicKeySignedPacketPayload).Load(validPublicKeySignedPacketPayloadKemPubKey)
		if err != nil || sigData.Signature == nil {
			return false
		}
		return sigData.Verify(sha256.New(), validPublicKeySignedPacketPayloadSigPubKey)
	})
	testOnePayload(t, marshal, packets.PacketHeader{ID: packets.PublicKeySignedPacketType, ConnectionUUID: connection, Time: pt}, GetInvalidPublicKeySignedPacketPayload(), func(o packets.PacketPayload, r packets.PacketPayload) bool {
		if !slices.Equal([]byte{0, 1, 2, 3}, r.(*packets.PublicKeySignedPacketPayload).SigPubKeyHash) {
			return false
		}
		sigData, err := r.(*packets.PublicKeySignedPacketPayload).Load(validPublicKeySignedPacketPayloadKemPubKey)
		return err != nil && sigData.Signature == nil
	})
}

func emptyPayloadChecker(o packets.PacketPayload, r packets.PacketPayload) bool {
	return true
}

func testOnePayload(t *testing.T, marshal *packets.PacketMarshaller, header packets.PacketHeader, payload packets.PacketPayload, payloadChecker func(o packets.PacketPayload, r packets.PacketPayload) bool) {
	err := marshal.Marshal(header, payload)
	assert.NoError(t, err)
	var rHeader *packets.PacketHeader
	var rPayload packets.PacketPayload
	err = packets.ErrFragmentReceived
	for errors.Is(err, packets.ErrFragmentReceived) {
		rHeader, rPayload, err = marshal.Unmarshal()
	}
	assert.NotNil(t, rHeader)
	assert.NoError(t, err)
	assert.NotNil(t, rPayload)
	if rHeader != nil {
		assert.True(t, header.Equals(*rHeader))
	}
	if rPayload != nil {
		assert.Equal(t, payload.Size(), rPayload.Size())
		assert.True(t, payloadChecker(payload, rPayload))
	}

}

func TestMTUWriterReader(t *testing.T) {
	a1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	a2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	buff := new(bytes.Buffer)
	writer := &mtuWriter{mtu: 8, target: buff}
	n, err := writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)

	n, err = writer.Write(a2)
	assert.Error(t, err)
	assert.Equal(t, packets.ErrTooMuchData, err)
	assert.NotEqual(t, 8, n)
	assert.Equal(t, 0, n)

	n, err = writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)

	n, err = writer.Write([]byte{1, 2, 3, 4})
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, 20, buff.Len())

	reader := &mtuReader{mtuBuff: make([]byte, 8), target: buff}

	data := make([]byte, 8)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.True(t, slices.Equal(a1, data))
	data = data[:6]

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.True(t, slices.Equal(a1[:6], data))
	data = make([]byte, 7)

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.NotEqual(t, 8, n)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal([]byte{1, 2, 3, 4, 0, 0, 0}, data))
}

func TestFixedTransport(t *testing.T) {
	const mtu = 10
	transport := &fixedTransport{queue: make([][]byte, 0)}
	writer := &mtuWriter{mtu: mtu, target: transport}
	reader := &mtuReader{mtuBuff: make([]byte, mtu), target: transport}
	a1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	a2 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	a3 := []byte{1, 2, 3, 4}

	n, err := writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)

	n, err = writer.Write(a2)
	assert.Error(t, err)
	assert.NotEqual(t, mtu, n)
	assert.Equal(t, 0, n)
	assert.Equal(t, packets.ErrTooMuchData, err)

	n, err = writer.Write(a1)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)

	n, err = writer.Write(a3)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	data := make([]byte, mtu)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, mtu, n)
	assert.True(t, slices.Equal(a1, data))
	data = data[:6]

	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 6, n)
	assert.True(t, slices.Equal(a1[:6], data))

	n, err = writer.Write(a3)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)

	data = make([]byte, 7)
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.NotEqual(t, 7, n)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal(a3, data[:4]))

	data = data[:4]
	n, err = reader.Read(data)
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.True(t, slices.Equal(a3, data))

	n, err = reader.Read(data)
	assert.Error(t, err)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

func newMTUTransport(mtu int) *mtuTransport {
	transport := &fixedTransport{queue: make([][]byte, 0)}
	return &mtuTransport{
		reader: &mtuReader{
			mtuBuff: make([]byte, mtu),
			target:  transport,
		},
		writer: &mtuWriter{
			mtu:    mtu,
			target: transport,
		},
	}
}

type mtuTransport struct {
	reader *mtuReader
	writer *mtuWriter
}

func (m *mtuTransport) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m *mtuTransport) Write(p []byte) (n int, err error) {
	return m.writer.Write(p)
}

type mtuReader struct {
	mtuBuff []byte
	target  io.Reader
}

func (m *mtuReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, err = m.target.Read(m.mtuBuff)
	n = copy(p, m.mtuBuff[:min(n, len(p))])
	return
}

type mtuWriter struct {
	mtu    int
	target io.Writer
}

func (m *mtuWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > m.mtu {
		return 0, packets.ErrTooMuchData
	}
	return m.target.Write(p)
}

type fixedTransport struct {
	queue [][]byte
}

func (m *fixedTransport) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(m.queue) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.queue[0])
	m.queue = m.queue[1:]
	return
}

func (m *fixedTransport) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	cpy := make([]byte, len(p))
	n = copy(cpy, p)
	m.queue = append(m.queue, cpy)
	return
}
