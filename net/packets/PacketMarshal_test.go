package packets

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io"
	"slices"
	"testing"
)

func TestPacketMarshal(t *testing.T) {

}

func TestPacketMarshalFragmented(t *testing.T) {

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

func TestMTUTransport(t *testing.T) {
	const mtu = 10
	transport := &mtuTransport{queue: make([][]byte, 0)}
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

type mtuTransport struct {
	queue [][]byte
}

func (m *mtuTransport) Read(p []byte) (n int, err error) {
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

func (m *mtuTransport) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	cpy := make([]byte, len(p))
	n = copy(cpy, p)
	m.queue = append(m.queue, cpy)
	return
}
