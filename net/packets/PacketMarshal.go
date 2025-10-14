package packets

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

var FragmentReceived = errors.New("fragment received")
var InvalidPacketID = errors.New("invalid packet id")
var FragmentIndexOutOfRange = errors.New("fragment index out of range")

type PacketPayload interface {
	io.WriterTo
	io.ReaderFrom
	Size() uint
	//TODO: Add hmac calculation (Via return a valid instance) and hmac receiver for support in marshal only
}

type PacketMarshaller struct {
	Conn io.ReadWriter
	// MTU Conn, maximum transmission unit, makes sure packets get fragmented if needed and enables buffer support when > 0; if 0, there is no length limit and no fragmentation
	MTU                    uint
	fragments              [][]byte
	fragmentedPacketHeader PacketHeader
	fragmentMutex          sync.Mutex
}

func (p *PacketMarshaller) Unmarshal() (packetHeader *PacketHeader, packetPayload PacketPayload, err error) {
	packetHeader = &PacketHeader{}
	var localConn io.ReadWriter
	if p.MTU > 0 {
		packetData := make([]byte, p.MTU)
		_, err = p.Conn.Read(packetData)
		if err != nil {
			return packetHeader, nil, err
		}
		localConn = bytes.NewBuffer(packetData)
	} else {
		localConn = p.Conn
	}
	_, err = packetHeader.ReadFrom(localConn)
	if err != nil {
		return packetHeader, nil, err
	}
	if packetHeader.IsFragment() {
		bts := make([]byte, packetHeader.fragmentSize)
		_, err = io.ReadFull(localConn, bts)
		if err != nil {
			return packetHeader, nil, err
		}
		return p.processFragment(bts, *packetHeader)
	} else {
		return p.unmarshal(*packetHeader, localConn)
	}
}

func (p *PacketMarshaller) unmarshal(header PacketHeader, conn io.Reader) (*PacketHeader, PacketPayload, error) {
	var pyld PacketPayload
	switch header.ID {
	case ConnectionRejectedPacketType, PublicKeyRequestPacketType, SignatureRequestPacketType, SignaturePublicKeyRequestPacketType:
		pyld = &EmptyPayload{}
	default:
		return header.Clone(), nil, InvalidPacketID
	}
	_, err := pyld.ReadFrom(conn)
	if err != nil {
		return header.Clone(), nil, err
	}
	return header.Clone(), pyld, nil
}

func (p *PacketMarshaller) Marshal(packetHeader PacketHeader, payload PacketPayload) error {
	if p.MTU > 0 {
		if HeaderSizeForFragmentation >= p.MTU {
			return MTUTooSmall
		} else {
			sz := payload.Size()
			var pw *packetFragmentWriter
			if sz+HeaderSize <= p.MTU {
				pw = &packetFragmentWriter{target: p.Conn, header: *packetHeader.Clone(), mtu: p.MTU}
			} else {
				fc := sz / (p.MTU - HeaderSizeForFragmentation)
				if sz%(p.MTU-HeaderSizeForFragmentation) > 0 {
					fc++
				}
				pw = &packetFragmentWriter{target: p.Conn, header: *packetHeader.CloneAsFragment(0, byte(fc), uint16(p.MTU-HeaderSizeForFragmentation)), mtu: p.MTU, fragmentWrite: true}
			}
			_, err := payload.WriteTo(pw)
			if err != nil {
				return err
			}
			if sz == 0 { // Dummy write if zero payload to force packetFragmentWriter init
				_, _ = pw.Write(nil)
			}
			err = pw.Flush()
			if err != nil {
				return err
			}
		}
	} else {
		_, err := packetHeader.Clone().WriteTo(p.Conn)
		if err != nil {
			return err
		}
		_, err = payload.WriteTo(p.Conn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PacketMarshaller) processFragment(f []byte, header PacketHeader) (*PacketHeader, PacketPayload, error) {
	p.fragmentMutex.Lock()
	defer p.fragmentMutex.Unlock()
	if len(p.fragments) != int(header.fragmentCount) || header.Equals(p.fragmentedPacketHeader) {
		p.fragments = make([][]byte, header.fragmentCount)
		p.fragmentedPacketHeader.Set(header)
	}
	if int(header.fragmentIndex) >= len(p.fragments) {
		return &header, nil, FragmentIndexOutOfRange
	}
	p.fragments[header.fragmentIndex] = f
	buff := new(bytes.Buffer)
	for _, f := range p.fragments {
		if f == nil {
			return &header, nil, FragmentReceived
		} else {
			buff.Write(f)
		}
	}
	defer p.clearFragmentCache()
	return p.unmarshal(p.fragmentedPacketHeader, buff)
}

func (p *PacketMarshaller) clearFragmentCache() {
	p.fragments = nil
	p.fragmentedPacketHeader.Clear()
}

func (p *PacketMarshaller) ClearFragmentCache() {
	p.fragmentMutex.Lock()
	defer p.fragmentMutex.Unlock()
	p.clearFragmentCache()
}
