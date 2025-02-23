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
	if s.outQueue == nil {
		panic("outQueue is nil")
	}
	elem := &outboundElement{}
	elem.buffer = s.Device.GetMessageBuffer()
	offset := MessageTransportHeaderSize

	elem.packet = elem.buffer[offset : offset+len(packet)+3]
	elem.packet[0] = 8 << 4
	binary.BigEndian.PutUint16(elem.packet[1:3], uint16(len(packet)))

	copy(elem.packet[3:], packet)
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

func (device *Device) routineSendPoly() {
	// poly sock
	for outEle := range device.net.polySocket.outQueue {
		if outEle == nil {
			return
		}
		peer := outEle.peer
		elemContainer := device.GetOutboundElementsContainer()
		elem := device.NewOutboundElement()
		elem.buffer = outEle.buffer
		elem.packet = outEle.packet
		elem.endpoint = outEle.ep
		elemContainer.elems = append(elemContainer.elems, elem)

		select {
		case peer.queue.staged <- elemContainer:
			peer.SendStagedPackets()
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemContainer)
		}
	}
}

func (s *PolySock) stop() {
	close(s.outQueue)
}
