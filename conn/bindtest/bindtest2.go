/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package bindtest

import (
	"fmt"
	"github.com/encodeous/polyamide/conn"
	"net"
	"net/netip"
	"slices"
)

type chanPkt struct {
	data   []byte
	remote ChannelEndpoint2
}

type ChannelBind2 struct {
	rx, tx      *chan chanPkt
	closeSignal chan bool
	epLookup    *[]string
	sendVia     func(to ChannelEndpoint2) ChannelEndpoint2
}

type ChannelEndpoint2 uint16

var (
	_ conn.Bind     = (*ChannelBind2)(nil)
	_ conn.Endpoint = (*ChannelEndpoint2)(nil)
)

func NewChannelBind2(epLookup *[]string, sendVia1, sendVia2 func(to ChannelEndpoint2) ChannelEndpoint2) [2]conn.Bind {
	arx4 := make(chan chanPkt, 8192)
	brx4 := make(chan chanPkt, 8192)
	var binds [2]ChannelBind2
	binds[0].rx = &arx4
	binds[0].tx = &brx4

	binds[1].rx = &brx4
	binds[1].tx = &arx4

	binds[0].epLookup = epLookup
	binds[1].epLookup = epLookup
	binds[0].sendVia = sendVia1
	binds[1].sendVia = sendVia2
	return [2]conn.Bind{&binds[0], &binds[1]}
}

func (c ChannelEndpoint2) ClearSrc() {}

func (c ChannelEndpoint2) SrcToString() string { return "" }

func (c ChannelEndpoint2) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", c) }

func (c ChannelEndpoint2) DstToBytes() []byte { return []byte{byte(c)} }

func (c ChannelEndpoint2) DstIP() netip.Addr { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }

func (c ChannelEndpoint2) SrcIP() netip.Addr { return netip.Addr{} }
func (c ChannelEndpoint2) DstIPPort() netip.AddrPort {
	return netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", c))
}

func (c *ChannelBind2) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.closeSignal = make(chan bool)
	fns = append(fns, c.makeReceiveFunc(*c.rx))
	return fns, port, nil
}

func (c *ChannelBind2) Close() error {
	if c.closeSignal != nil {
		select {
		case <-c.closeSignal:
		default:
			close(c.closeSignal)
		}
	}
	return nil
}

func (c *ChannelBind2) BatchSize() int { return 1 }

func (c *ChannelBind2) SetMark(mark uint32) error { return nil }

func (c *ChannelBind2) makeReceiveFunc(ch chan chanPkt) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		select {
		case <-c.closeSignal:
			return 0, net.ErrClosed
		case rx := <-ch:
			copied := copy(bufs[0], rx.data)
			sizes[0] = copied
			eps[0] = rx.remote
			return 1, nil
		}
	}
}

func (c *ChannelBind2) Send(bufs [][]byte, ep conn.Endpoint) error {
	outEp := c.sendVia(*ep.(*ChannelEndpoint2))
	for _, b := range bufs {
		select {
		case <-c.closeSignal:
			return net.ErrClosed
		default:
			bc := make([]byte, len(b))
			copy(bc, b)
			*c.tx <- chanPkt{
				data:   bc,
				remote: outEp,
			}
		}
	}
	return nil
}

func (c *ChannelBind2) ParseEndpoint(s string) (conn.Endpoint, error) {
	return ChannelEndpoint2(slices.Index(*c.epLookup, s)), nil
}
