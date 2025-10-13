package packets

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"
)

type PacketType byte

const HeaderSize = 1 + 16 + 8
const HeaderSizeForFragmentation = HeaderSize + 1 + 1 + 2

var TimeOutOfRange = errors.New("time out of range")

type PacketHeader struct {
	ID             PacketType
	ConnectionUUID [16]byte
	Time           time.Time
	fragmentIndex  byte
	fragmentCount  byte
	fragmentSize   uint16
}

func (h *PacketHeader) WriteTo(w io.Writer) (n int64, err error) {
	m, err := w.Write([]byte{byte(h.ID)})
	n = int64(m)
	if err != nil {
		return n, err
	}
	m, err = w.Write(h.ConnectionUUID[:])
	n += int64(m)
	if err != nil {
		return n, err
	}
	bts := make([]byte, 8)
	if h.Time.UnixMilli() < 0 {
		return n, TimeOutOfRange
	}
	binary.LittleEndian.PutUint64(bts, uint64(h.Time.UnixMilli()))
	m, err = w.Write(bts)
	n += int64(m)
	if err != nil {
		return n, err
	}
	if h.IsFragment() {
		m, err = w.Write([]byte{h.fragmentIndex, h.fragmentCount})
		n += int64(m)
		if err != nil {
			return n, err
		}
		bts = make([]byte, 2)
		binary.LittleEndian.PutUint16(bts, h.fragmentSize)
		m, err = w.Write(bts)
		n += int64(m)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (h *PacketHeader) ReadFrom(r io.Reader) (n int64, err error) {
	bts := make([]byte, 1)
	m, err := io.ReadFull(r, bts)
	n += int64(m)
	if err != nil {
		return n, err
	}
	h.ID = PacketType(bts[0])
	m, err = io.ReadFull(r, h.ConnectionUUID[:])
	n += int64(m)
	if err != nil {
		return n, err
	}
	bts = make([]byte, 8)
	m, err = io.ReadFull(r, bts)
	n += int64(m)
	if err != nil {
		return n, err
	}
	tms := binary.LittleEndian.Uint64(bts)
	if tms > math.MaxInt64 {
		return n, TimeOutOfRange
	}
	h.Time = time.UnixMilli(int64(tms))
	if h.IsFragment() {
		bts = make([]byte, 2)
		m, err = io.ReadFull(r, bts)
		n += int64(m)
		if err != nil {
			return n, err
		}
		h.fragmentIndex = bts[0]
		h.fragmentCount = bts[1]
		m, err = io.ReadFull(r, bts)
		n += int64(m)
		if err != nil {
			return n, err
		}
		h.fragmentSize = binary.LittleEndian.Uint16(bts)
	}
	return n, nil
}

func (h *PacketHeader) IsFragment() bool {
	return byte(h.ID)&byte(128) > 0
}

// GetActualID returns the actual ID regardless of IsFragment being true
func (h *PacketHeader) GetActualID() PacketType {
	return PacketType(byte(h.ID) & ^(byte(128)))
}

func (h *PacketHeader) Set(other PacketHeader) {
	h.ID = other.GetActualID()
	h.ConnectionUUID = other.ConnectionUUID
	h.Time = other.Time
}

func (h *PacketHeader) Equals(other PacketHeader) bool {
	return h.GetActualID() == other.GetActualID() && h.ConnectionUUID == other.ConnectionUUID && h.Time.Equal(other.Time)
}

func (h *PacketHeader) Clear() {
	h.ID = 0
	h.ConnectionUUID = [16]byte{}
	h.Time = time.Time{}
	h.fragmentIndex = 0
	h.fragmentCount = 0
	h.fragmentSize = 0
}

func (h *PacketHeader) Clone() *PacketHeader {
	return &PacketHeader{
		ID:             h.GetActualID(),
		ConnectionUUID: h.ConnectionUUID,
		Time:           h.Time,
	}
}

func (h *PacketHeader) CloneAsFragment(index, count byte, size uint16) *PacketHeader {
	return &PacketHeader{
		ID:             PacketType(byte(h.ID) | byte(128)),
		ConnectionUUID: h.ConnectionUUID,
		Time:           h.Time,
		fragmentIndex:  index,
		fragmentCount:  count,
		fragmentSize:   size,
	}
}
