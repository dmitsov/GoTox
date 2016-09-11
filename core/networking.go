package core

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const InvalidSocket = 0

const (
	MaxUdpPacketSize = 2048

	//packet identifiers
	NetPacketPingRequest    = 0  /* Ping request packet ID. */
	NetPacketPingResponse   = 1  /* Ping response packet ID. */
	NetPacketGetNodes       = 2  /* Get nodes request packet ID. */
	NetPacketSendNodesIPv6  = 4  /* Send nodes response packet ID for other addresses. */
	NetPacketCookieRequest  = 24 /* Cookie request packet */
	NetPacketCookieResponse = 25 /* Cookie response packet */
	NetPacketCryptoHS       = 26 /* Crypto handshake packet */
	NetPacketCryptoData     = 27 /* Crypto data packet */
	NetPacketCrypto         = 32 /* Encrypted data packet ID. */
	NetPacketLANDiscovery   = 33 /* LAN discovery packet ID. */
)

//hardening packets
const (
	NetPacketOnionSendInitial = 128
	NetPacketOnionSend1       = 129
	NetPacketOnionSend2       = 130

	NetPacketAnnounceRequest   = 131
	NetPacketAnnounceResponse  = 132
	NetPacketOnionDataRequest  = 133
	NetPacketOnionDataResponse = 134

	NetPacketOnionRecv3 = 140
	NetPacketOnionRecv2 = 141
	NetPacketOnionRecv1 = 142

	/* Only used for bootstrap nodes */
	BootstrapInfoPacketID = 240

	ToxPortrangeFrom = 33445
	ToxPortrangeTo   = 33545
	ToxPortDefault   = ToxPortrangeFrom
)

const (
	TcpOnionFamily = syscall.AF_INET6 + 1
	TcpInet        = syscall.AF_INET6 + 2
	TcpInet6       = syscall.AF_INET6 + 3
	TcpFamily      = syscall.AF_INET6 + 4
)

type PackageHandler func(data []byte, ip net.IP, port uint16)

type Networking_Core struct {
	isPollingStarted bool
	handlers         map[byte]PackageHandler
	coreAddr         *net.UDPAddr
	ip               net.IP
	port             uint16
	Conn             *net.UDPConn
	wg               sync.WaitGroup
	mutx             sync.RWMutex
	killChan         chan struct{}
	killComplete     chan struct{}
}

type receivedPacket struct {
	data []byte
	ip   net.IP
	port uint16
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
	return int(f.Fd()) == InvalidSocket
}

func IsIPv4(ip net.IP) bool {
	if len(ip) != net.IPv4len || len(ip) != net.IPv6len {
		return false
	}

	return ip.To4() != nil
}

var (
	startTime time.Time
)

func InitiateMonotonicTime() {
	startTime = time.Now()
}

//
func GetTimeMonotonic() uint64 {
	var nanoSeconds int64 = time.Since(startTime).Nanoseconds()
	if nanoSeconds < 0 {
		return 0
	}

	var millisecondsMono int64 = nanoSeconds / int64(time.Millisecond)
	return uint64(millisecondsMono)
}

//current time in microseconds
//have to check Tox lib to be sure
func GetCurrentTime() uint64 {
	return uint64(time.Now().UnixNano() / int64(time.Microsecond))
}

func SetSocketReuseaddr(sock int) error {
	var value int = 1
	err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, value)
	if err != nil {
		fmt.Printf("Error occured in setting SO_REUSEADDR: ", err)
	}

	return err
}

func SetDualStack(sock int) error {

	var val int
	val, err := syscall.GetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPPROTO_IPV6)
	if err == nil && val == 0 {
		return nil
	}
	fmt.Println("Dual stack error ", err)

	err = syscall.SetsockoptInt(sock, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
	if err != nil {
		fmt.Println("Error in setting dualstack ", err)
	}
	return err
}

func InitNetworking(ip net.IP, port uint16) (*Networking_Core, error) {
	return InitNetworkingCore(ip, port, port+uint16(ToxPortrangeTo-ToxPortrangeFrom))
}

func InitNetworkingCore(ip net.IP, port_from, port_to uint16) (*Networking_Core, error) {
	if port_from == 0 && port_to == 0 {
		port_from = ToxPortrangeFrom
		port_to = ToxPortrangeTo
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
			defer f.Close()
			sock := int(f.Fd())
			if len(ip) == net.IPv6len {
				err = SetDualStack(sock)
				if err != nil {
					return nil, err
				}
				var mreqAddr [16]byte
				mreqAddr[0], mreqAddr[1], mreqAddr[15] = 0xFF, 0x02, 0x01

				ip6mreq := &syscall.IPv6Mreq{mreqAddr, 0}

				err = syscall.SetsockoptIPv6Mreq(sock, syscall.IPPROTO_IPV6, syscall.IPV6_ADD_MEMBERSHIP, ip6mreq)
				if err != nil {
					fmt.Println("Not able to set the ip6mreq option: ", err.Error())
					return nil, err
				}
			}

			if err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
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
			netCore.handlers = make(map[byte]PackageHandler)
			netCore.ip = ip
			netCore.port = p
			netCore.coreAddr = udpAddr
			netCore.Conn = conn
			netCore.killChan = make(chan struct{})
			netCore.killComplete = make(chan struct{})
			return netCore, nil
		}
	}

	fmt.Println("Failed to establish a listening udp port")

	return nil, &NetError{"Couldn't bind to the specified ports", ip, port_from}
}

func (n *Networking_Core) Kill() {
	if n == nil {
		return
	}

	if n.Conn != nil {
		n.Conn.Close()
	}

	if n.isPollingStarted {
		fmt.Println("Stopping poll goroutine")
		n.killChan <- struct{}{}
		<-n.killChan
		close(n.killChan)
	}
	fmt.Println("Stopping networking core")
	n.wg.Wait()
}

func (n *Networking_Core) AddHandler(start byte, handler PackageHandler) {
	n.mutx.Lock()
	defer n.mutx.Unlock()
	n.handlers[start] = handler
}

func (n *Networking_Core) DeleteHandler(start byte) {
	n.mutx.Lock()
	defer n.mutx.Unlock()
	delete(n.handlers, start)
}

func (n *Networking_Core) SendPacket(ip net.IP, port uint16, data []byte) error {
	if n.Conn == nil {
		return &NetError{"Networking core not initialized", nil, 0}
	}

	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return &NetError{"Invalid send ip address", ip, port}
	}

	sendAddr := new(net.UDPAddr)
	sendAddr.IP = ip
	sendAddr.Port = int(port)
	if _, err := n.Conn.WriteTo(data, sendAddr); err != nil {
		return err
	}

	return nil
}

func (n *Networking_Core) ReceivePacket() ([]byte, net.Addr, error) {
	data := make([]byte, MaxUdpPacketSize)
	length, addr, err := n.Conn.ReadFrom(data)
	if err != nil {
		return nil, nil, err
	}
	data = data[:length]

	return data, addr, nil
}

func (n *Networking_Core) Poll() {
	if n.Conn == nil {
		return
	}

	receivedDataChan := make(chan *receivedPacket)
	polling := func() {
		for {
			data, addr, err := n.ReceivePacket()
			opError, _ := err.(*net.OpError)
			if opError != nil && opError.Err.Error() == "use of closed network connection" {
				close(receivedDataChan)
				fmt.Println("Socket closed")
				return
			} else if opError != nil {
				fmt.Println("Error in receiving data from udp socket ", err)
				return
			}
			udpAddr := addr.(*net.UDPAddr)
			packet := &receivedPacket{data, udpAddr.IP, uint16(udpAddr.Port)}
			receivedDataChan <- packet
		}

	}

	n.isPollingStarted = true
	go polling()
	for {
		select {
		case <-n.killChan:
			fmt.Println("Polling finished")
			n.killChan <- struct{}{}
			return
		case packet := <-receivedDataChan:

			if len(packet.data) == 0 {
				continue
			}

			//have to think of a better way to use mutexes and sem-chan
			n.mutx.RLock()
			handler, ok := n.handlers[packet.data[0]]
			n.mutx.RUnlock()
			if !ok {
				fmt.Println("Unrecognised message")
				continue
			}

			packet.data = packet.data[1:]
			n.wg.Add(1)
			go func() {
				handler(packet.data, packet.ip, packet.port)
				n.wg.Done()
			}()
		}
	}
}

func ipIsset(ip net.IP) bool {
	var isValid bool = len(ip) == net.IPv4len || len(ip) == net.IPv6len
	if isValid {
		isValid = !ip.Equal(net.IPv4Zero) && !ip.Equal(net.IPv6Zero)
	}

	return isValid
}

func ipPortIsSet(ipPort *net.UDPAddr) bool {
	return ipPort.Port > 0 && ipIsset(ipPort.IP)
}
