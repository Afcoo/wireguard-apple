//go:build darwin

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Afcoo.
 */

package main

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// darwinDirectBind is a narrow adaptation of wireguard-go's StdNetBind.
// NetworkExtension scopes provider-originated BSD sockets to the default
// hardware interface. That skips a directly connected Virtualization NAT
// endpoint, even when the system route points at the VZNAT bridge. Before a
// datagram is sent to a directly connected endpoint, bind its socket to the
// interface whose address prefix contains that endpoint.
//
// ThruRNDIS has one peer on one directly connected VZNAT network. Endpoints
// outside a directly connected prefix retain the upstream unbound behavior.
type darwinDirectBind struct {
	mu sync.Mutex

	ipv4 *net.UDPConn
	ipv6 *net.UDPConn

	boundInterface4 int
	boundInterface6 int
}

type darwinDirectEndpoint netip.AddrPort

var (
	_ conn.Bind     = (*darwinDirectBind)(nil)
	_ conn.Endpoint = darwinDirectEndpoint{}
)

func newWireGuardBind() conn.Bind {
	return &darwinDirectBind{}
}

func (*darwinDirectBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	endpoint, err := netip.ParseAddrPort(value)
	return darwinDirectEndpoint(endpoint), err
}

func (darwinDirectEndpoint) ClearSrc() {}

func (endpoint darwinDirectEndpoint) DstIP() netip.Addr {
	return netip.AddrPort(endpoint).Addr()
}

func (darwinDirectEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (endpoint darwinDirectEndpoint) DstToBytes() []byte {
	bytes, _ := netip.AddrPort(endpoint).MarshalBinary()
	return bytes
}

func (endpoint darwinDirectEndpoint) DstToString() string {
	return netip.AddrPort(endpoint).String()
}

func (darwinDirectEndpoint) SrcToString() string {
	return ""
}

func listenDarwinUDP(network string, port int) (*net.UDPConn, int, error) {
	socket, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
	if err != nil {
		return nil, 0, err
	}

	localAddress, err := net.ResolveUDPAddr(
		socket.LocalAddr().Network(),
		socket.LocalAddr().String(),
	)
	if err != nil {
		socket.Close()
		return nil, 0, err
	}
	return socket, localAddress.Port, nil
}

func (bind *darwinDirectBind) Open(requestedPort uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	if bind.ipv4 != nil || bind.ipv6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	var attempts int
	for {
		port := int(requestedPort)
		ipv4, actualPort, ipv4Error := listenDarwinUDP("udp4", port)
		if ipv4Error != nil && !errors.Is(ipv4Error, syscall.EAFNOSUPPORT) {
			return nil, 0, ipv4Error
		}

		ipv6, actualPort, ipv6Error := listenDarwinUDP("udp6", actualPort)
		if requestedPort == 0 && errors.Is(ipv6Error, syscall.EADDRINUSE) && attempts < 100 {
			if ipv4 != nil {
				_ = ipv4.Close()
			}
			attempts++
			continue
		}
		if ipv6Error != nil && !errors.Is(ipv6Error, syscall.EAFNOSUPPORT) {
			if ipv4 != nil {
				_ = ipv4.Close()
			}
			return nil, 0, ipv6Error
		}

		var receiveFunctions []conn.ReceiveFunc
		if ipv4 != nil {
			bind.ipv4 = ipv4
			receiveFunctions = append(receiveFunctions, makeDarwinReceive(ipv4))
		}
		if ipv6 != nil {
			bind.ipv6 = ipv6
			receiveFunctions = append(receiveFunctions, makeDarwinReceive(ipv6))
		}
		if len(receiveFunctions) == 0 {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		return receiveFunctions, uint16(actualPort), nil
	}
}

func makeDarwinReceive(socket *net.UDPConn) conn.ReceiveFunc {
	return func(buffer []byte) (int, conn.Endpoint, error) {
		length, endpoint, err := socket.ReadFromUDPAddrPort(buffer)
		return length, darwinDirectEndpoint(endpoint), err
	}
}

func (bind *darwinDirectBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var ipv4Error, ipv6Error error
	if bind.ipv4 != nil {
		ipv4Error = bind.ipv4.Close()
		bind.ipv4 = nil
	}
	if bind.ipv6 != nil {
		ipv6Error = bind.ipv6.Close()
		bind.ipv6 = nil
	}
	bind.boundInterface4 = 0
	bind.boundInterface6 = 0

	if ipv4Error != nil {
		return ipv4Error
	}
	return ipv6Error
}

func (*darwinDirectBind) SetMark(uint32) error {
	return nil
}

func (bind *darwinDirectBind) Send(buffer []byte, endpoint conn.Endpoint) error {
	directEndpoint, ok := endpoint.(darwinDirectEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	destination := netip.AddrPort(directEndpoint)

	bind.mu.Lock()
	socket := bind.ipv4
	boundInterface := &bind.boundInterface4
	if destination.Addr().Is6() {
		socket = bind.ipv6
		boundInterface = &bind.boundInterface6
	}
	if socket == nil {
		bind.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}

	interfaceIndex := directlyConnectedInterfaceIndex(destination.Addr())
	if interfaceIndex != *boundInterface {
		if err := bindSocketToInterface(socket, destination.Addr().Is6(), interfaceIndex); err != nil {
			bind.mu.Unlock()
			return err
		}
		*boundInterface = interfaceIndex
	}
	bind.mu.Unlock()

	_, err := socket.WriteToUDPAddrPort(buffer, destination)
	return err
}

func directlyConnectedInterfaceIndex(destination netip.Addr) int {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0
	}

	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Contains(destination) {
				return networkInterface.Index
			}
		}
	}
	return 0
}

func bindSocketToInterface(socket *net.UDPConn, isIPv6 bool, interfaceIndex int) error {
	rawConnection, err := socket.SyscallConn()
	if err != nil {
		return err
	}

	var socketError error
	err = rawConnection.Control(func(fileDescriptor uintptr) {
		if isIPv6 {
			socketError = unix.SetsockoptInt(
				int(fileDescriptor),
				unix.IPPROTO_IPV6,
				unix.IPV6_BOUND_IF,
				interfaceIndex,
			)
		} else {
			socketError = unix.SetsockoptInt(
				int(fileDescriptor),
				unix.IPPROTO_IP,
				unix.IP_BOUND_IF,
				interfaceIndex,
			)
		}
	})
	if err != nil {
		return err
	}
	return socketError
}
