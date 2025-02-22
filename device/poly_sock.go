package device

import (
	"encoding/binary"
	"github.com/encodeous/polyamide/conn"
)

type outboundElement struct {
	buffer *[MaxMessageSize]byte // slice holding the packet data
	packet []byte                // slice of "buffer" (always!)
	ep     conn.Endpoint
	peer   *Peer
}

type PolySock struct {
	recv     PolyReceiver
	outQueue chan *outboundElement
	Device   *Device
}

type PolyReceiver interface {
	// Receive takes in PolyReceiver packets from the Polyamide listener. It must not block, and the packet bytes are not owned by the Receive function.
	Receive(packet []byte, endpoint conn.Endpoint, peer *Peer)
}

func (s *PolySock) Send(packet []byte, endpoint conn.Endpoint, peer *Peer) {
	if len(packet) > MaxMessageSize-3 {
		panic("packet too large")
	}
	elem := &outboundElement{}
	elem.buffer = s.Device.GetMessageBuffer()
	copy(elem.buffer[3:], packet)
	elem.buffer[0] = 7
	binary.LittleEndian.PutUint16(elem.buffer[1:3], uint16(len(packet)))
	elem.packet = elem.buffer[:3+len(packet)]
	elem.ep = endpoint
	elem.peer = peer
	s.outQueue <- elem
}

func newPolySock(dev *Device) *PolySock {
	return &PolySock{
		recv:     nil,
		outQueue: make(chan *outboundElement),
		Device:   dev,
	}
}

func (s *PolySock) stop() {
	s.outQueue <- nil
}
