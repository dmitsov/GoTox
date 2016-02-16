package core

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	INVALID_SOCKET = 0
)

const (
	MAX_UDP_PACKET_SIZE = 2048

	//packet identifiers
	NET_PACKET_PING_REQUEST    = 0  /* Ping request packet ID. */
	NET_PACKET_PING_RESPONSE   = 1  /* Ping response packet ID. */
	NET_PACKET_GET_NODES       = 2  /* Get nodes request packet ID. */
	NET_PACKET_SEND_NODES_IPV6 = 4  /* Send nodes response packet ID for other addresses. */
	NET_PACKET_COOKIE_REQUEST  = 24 /* Cookie request packet */
	NET_PACKET_COOKIE_RESPONSE = 25 /* Cookie response packet */
	NET_PACKET_CRYPTO_HS       = 26 /* Crypto handshake packet */
	NET_PACKET_CRYPTO_DATA     = 27 /* Crypto data packet */
	NET_PACKET_CRYPTO          = 32 /* Encrypted data packet ID. */
	NET_PACKET_LAN_DISCOVERY   = 33 /* LAN discovery packet ID. */
)

//hardening packets
const (
	NET_PACKET_ONION_SEND_INITIAL = 128
	NET_PACKET_ONION_SEND_1       = 129
	NET_PACKET_ONION_SEND_2       = 130

	NET_PACKET_ANNOUNCE_REQUEST    = 131
	NET_PACKET_ANNOUNCE_RESPONSE   = 132
	NET_PACKET_ONION_DATA_REQUEST  = 133
	NET_PACKET_ONION_DATA_RESPONSE = 134

	NET_PACKET_ONION_RECV_3 = 140
	NET_PACKET_ONION_RECV_2 = 141
	NET_PACKET_ONION_RECV_1 = 142

	/* Only used for bootstrap nodes */
	BOOTSTRAP_INFO_PACKET_ID = 240

	TOX_PORTRANGE_FROM = 33445
	TOX_PORTRANGE_TO   = 33545
	TOX_PORT_DEFAULT   = TOX_PORTRANGE_FROM
)

const (
	TCP_ONION_FAMILY = syscall.AF_INET6 + 1
	TCP_INET         = syscall.AF_INET6 + 2
	TCP_INET6        = syscall.AF_INET6 + 3
	TCP_FAMILY       = syscall.AF_INET6 + 4
)

type PackageHandler func(object interface{}, data []byte, ip net.IP, port uint16)

type Handler struct {
	handlerFunc PackageHandler
	object      interface{}
}

type Networking_Core struct {
	handlers map[byte]Handler
	coreAddr *net.UDPAddr
	ip       net.IP
	port     uint16
	Conn     *net.UDPConn
	wg       sync.WaitGroup
	isClosed bool
}

type NetError struct {
	errMsg string
	ip     net.IP
	port   uint16
}

func (e *NetError) Error() string {
	return fmt.Sprintf("%s IP: %s, Port: %d", e.errMsg, e.ip.String(), e.port)
}

func IsValidSock(c *net.UDPConn) bool {
	f, err := c.File()
	if err != nil {
		fmt.Println("Socket not right")
		return false
	}
	return int(f.Fd()) == INVALID_SOCKET
}

var (
	start_time time.Time
)

func initiate_monotonic_time() {
	start_time = time.Now()
}

func get_time_monotonic() uint64 {
	var nanoSeconds int64 = time.Since(start_time).Nanoseconds()
	if nanoSeconds < 0 {
		return 0
	}

	var milisecondsMono int64 = nanoSeconds / int64(time.Millisecond)
	return uint64(milisecondsMono)
}

func get_current_time() uint64 {
	return uint64(time.Now().UnixNano() / int64(time.Microsecond))
}

func SetSocketReuseaddr(c *net.UDPConn) error {
	f, err := c.File()
	if err != nil {
		fmt.Println("Socket not right! Can't set reuseaddr!")
		return err
	}
	sock := int(f.Fd())
	err = syscall.SetsockoptByte(sock, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		fmt.Printf("Error occured in setting SO_REUSEADDR: ", err)
	}

	return err
}

func SetDualStack(c *net.UDPConn) error {
	f, err := c.File()
	if err != nil {
		fmt.Println("Socket not right! Can't set dualstack!")
		return err
	}
	sock := int(f.Fd())
	var val int
	val, err = syscall.GetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPPROTO_IPV6)
	if err == nil && val == 0 {
		return nil
	}

	err = syscall.SetsockoptByte(sock, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
	if err != nil {
		fmt.Println("Error in setting dualstack ", err)
	}
	return err
}

func InitNetworkingCore(ip net.IP, port_from, port_to uint16) (*Networking_Core, error) {
	if port_from == 0 && port_to == 0 {
		port_from = TOX_PORTRANGE_FROM
		port_to = TOX_PORTRANGE_TO
	} else if port_from == 0 && port_to != 0 {
		port_from = port_to
	} else if port_from != 0 && port_to == 0 {
		port_to = port_from
	} else if port_from > port_to {
		port_from, port_to = port_to, port_from
	}

	if ip.IsLoopback() || ip.IsMulticast() ||
		ip.Equal(net.IPv4bcast) || ip.IsUnspecified() || (len(ip) != net.IPv4len && len(ip) != net.IPv6len) {
		return nil, &NetError{"Invalid address.", ip, port_from}
	}

	netCore := new(Networking_Core)

	for p := port_from; p <= port_to; p++ {
		udpAddr := new(net.UDPAddr)
		udpAddr.IP = ip
		udpAddr.Port = int(p)

		conn, err := net.ListenUDP("udp", udpAddr)
		if err == nil {
			f, _ := conn.File()

			sock := int(f.Fd())
			if len(ip) == net.IPv6len {
				SetDualStack(conn)
				var mreqAddr [16]byte
				mreqAddr[0], mreqAddr[1], mreqAddr[15] = 0xFF, 0x02, 0x01

				ip6mreq := &syscall.IPv6Mreq{mreqAddr, 0}

				err = syscall.SetsockoptIPv6Mreq(sock, syscall.IPPROTO_IPV6, syscall.IPV6_ADD_MEMBERSHIP, ip6mreq)
				if err != nil {
					fmt.Println("Not able to set the ip6mreq option: ", err.Error())
					return nil, err
				}
			}

			if err = syscall.SetsockoptByte(sock, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
				return nil, err
			}

			if err = syscall.SetNonblock(sock, true); err != nil {
				return nil, err
			}

			var bufferSize int = 2 * 1024 * 1024
			if err = conn.SetReadBuffer(bufferSize); err != nil {
				return nil, err
			}

			if err = conn.SetWriteBuffer(bufferSize); err != nil {
				return nil, err
			}
			netCore.handlers = make(map[byte]Handler)
			netCore.ip = ip
			netCore.port = p
			netCore.coreAddr = udpAddr
			netCore.Conn = conn
			return netCore, nil
		}
	}

	fmt.Println("Failed to establish a listening udp port")

	return nil, &NetError{"Couldn't bind to the specified ports", ip, port_from}
}

func (n *Networking_Core) KillNetworkingCore() {
	n.isClosed = true
	n.wg.Wait()
	if n.Conn != nil {
		n.Conn.Close()
	}
}

func (n *Networking_Core) AddHandler(start byte, handler PackageHandler, object interface{}) {
	n.handlers[start] = Handler{handler, object}
}

func (n *Networking_Core) sendpacket(ip net.IP, port uint16, data []byte) error {
	if n.Conn == nil {
		return &NetError{"Networking core not initialized", nil, 0}
	}

	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return &NetError{"Invalid send ip address", ip, port}
	}

	sendAddr := new(net.UDPAddr)
	sendAddr.IP = ip
	sendAddr.Port = int(port)

	if _, err := n.Conn.WriteToUDP(data, sendAddr); err != nil {
		return err
	}

	return nil
}

func (n *Networking_Core) receivepacket(ip *net.IP, port *uint16, data *[]byte) (uint64, error) {
	length, addr, err := n.Conn.ReadFromUDP(*data)
	if err != nil {
		return 0, nil
	}

	*ip = addr.IP
	*port = uint16(addr.Port)

	return uint64(length), nil
}

func (n *Networking_Core) networking_poll() {
	if n.Conn == nil {
		return
	}

	var ip net.IP
	var port uint16

	for {
		if n.isClosed {
			return
		}

		var data []byte
		length, err := n.receivepacket(&ip, &port, &data)
		if err != nil {
			fmt.Println("Error in receiving data from udp socket")
			return
		}

		if length == 0 {
			continue
		}

		handler, ok := n.handlers[data[0]]
		if !ok {
			fmt.Println("Unrecognised message")
			continue
		}

		n.wg.Add(1)
		go func() {
			handler.handlerFunc(handler.object, data, ip, port)
			n.wg.Done()
		}()
	}
}
