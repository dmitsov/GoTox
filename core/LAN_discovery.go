package core

import (
	"net"
	//"syscall"
	//"os"
	//"unsafe"
	"fmt"
)

/*Type for describing errors in
  LAN operations. It contains the error message
  and an ip address if the operation sending packets to the
  LAN network
*/
type LANError struct {
	errorMsg string
	ip       net.IP
}

//Returns the error message and the ip address that was used if there was one
func (e *LANError) Error() string {
	return e.errorMsg + fmt.Sprintf(" IP:%s", e.ip)
}

//This method return a slice of ip - ports
func fetchBroadcastInfo(port uint16) ([]net.Addr, error) {
	brAddrs := make([]net.Addr, 0)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, &LANError{"LANError couldn't get all the network addresses" + err.Error(), nil}
	}

	for _, v := range addrs {
		var network *net.IPNet
		_, network, err = net.ParseCIDR(v.String())
		if len(network.IP) == net.IPv6len {
			continue
		}

		broadcastAddr := make(net.IP, 4)
		copy(broadcastAddr, network.IP)
		for i, b := range network.Mask {
			broadcastAddr[i] |= ^b
		}

		ipPort := new(net.UDPAddr) // there isn't any difference between UDPAddr and TCPAddr so I'm using

		ipPort.IP = broadcastAddr
		ipPort.Port = int(port)
		brAddrs = append(brAddrs, ipPort)
	}

	return brAddrs, nil
}

func IsLAN(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	if len(ip) == net.IPv4len {
		switch {
		case ip[0] == 10:
			return true
		case ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31:
			return true
		case ip[0] == 192 && ip[1] == 168:
			return true
		case ip[0] == 169 && ip[1] == 254 && ip[2] != 0 && ip[2] != 255:
			return true
		case ip[0] == 100 && (ip[1]&0xC0) == 0x40:
			return true
		default:
			return false
		}
	} else if len(ip) == net.IPv6len {
		if (ip[1] == 0xFF && ip[1] < 3 && ip[15] == 1) || (ip[0] == 0xFE && (ip[1]&0xC0) == 0x80) {
			return true
		}

		if ip4 := ip.To4(); ip4 != nil {
			return IsLAN(ip4)
		}
	}

	return false
}

//Send a packet to every LAN host
func (n *Networking_Core) SendBroadcast(port uint16, data []byte) error {
	broadcast_addressess, err := fetchBroadcastInfo(port)

	if err != nil {
		return err
	}

	if len(broadcast_addressess) == 0 {
		return &LANError{"No broadcast addresses found", nil}
	}

	for _, addr := range broadcast_addressess {
		realAddr := addr.(*net.UDPAddr)
		n.SendPacket(realAddr.IP, uint16(realAddr.Port), data)
	}

	return nil
}
