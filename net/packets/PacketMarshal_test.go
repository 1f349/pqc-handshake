package packets

import (
	"bytes"
	"errors"
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

func sharedPacketMarshalTest(t *testing.T, transport io.ReadWriter, mtu uint) {
	marshal := &PacketMarshaller{
		Conn: transport,
		MTU:  mtu,
	}
	connection := GetUUID()
	pt := MilliTime(time.Now())
	testOnePayload(t, marshal, PacketHeader{ID: ConnectionRejectedPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, true)
	testOnePayload(t, marshal, PacketHeader{ID: PublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, true)
	testOnePayload(t, marshal, PacketHeader{ID: SignatureRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, true)
	testOnePayload(t, marshal, PacketHeader{ID: SignaturePublicKeyRequestPacketType, ConnectionUUID: connection, Time: pt}, ValidEmptyPayload, true)
}

func testOnePayload(t *testing.T, marshal *PacketMarshaller, header PacketHeader, payload PacketPayload, succeed bool) {
	err := marshal.Marshal(header, payload)
	if succeed {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
	}
	var rHeader *PacketHeader
	var rPayload PacketPayload
	err = FragmentReceived
	for errors.Is(err, FragmentReceived) {
		rHeader, rPayload, err = marshal.Unmarshal()
	}
	assert.NotNil(t, rHeader)
	if succeed {
		assert.NoError(t, err)
		assert.NotNil(t, rPayload)
		if rHeader != nil {
			assert.True(t, header.Equals(*rHeader))
		}
		if rPayload != nil {
			assert.Equal(t, payload.Size(), rPayload.Size())
		}
	} else {
		assert.Error(t, err)
		assert.Nil(t, rPayload)
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
	assert.Equal(t, TooMuchData, err)
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
	assert.Equal(t, TooMuchData, err)

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
		return 0, TooMuchData
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
