package core

import(
	"net"
	"syscall"
	"os"
	"unsafe"
	"fmt"
)

type LANError struct {
	errorMsg string
	ip	net.IP
}

func (e *LANError) Error() string {
	return errorMsg + fmt.Sprintf(" IP:%s",ip)
}

func fetch_broadcast_info(port uint16) ([]net.Addr,error) ([]*net.UDPAddr,error) {
	b := make([]byte,1000)
	var l uint32 = 1000
	aList := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	
	err := syscall.GetAdaptersInfo(aList,&l)
	
	if err != nil {
		return nil, os.NewSyscallError("GetAddrInfo",err)
	}

	ip_ports := make([]*net.UDPAddr,0)
	
	for ai := aList; ai != nil; ai = ai.Next {
		addr := new(net.UDPAddr)
		addr.Port = int(port)

		mask := net.ParseIP(ai.IpAddressList.IpMask)
		gateway := net.ParseIP(ai.GatewayList.IpAddress)
		gateway[0] += ^mask[0]
		gateway[1] += ^mask[1]
		gateway[2] += ^mask[2]
		gateway[3] += ^mask[3] - 1
		
		addr.IP = gateway
		ip_ports = append(ip_ports,addr)
	} 

	return ip_ports,nil
}

func (net *Networking_Core) sendbroadcast(port uint16, data []byte) error {
	broadcast_addresses,err := fetch_broadcast_info(port)
	
	if err != nil {
		return err
	}

	if len(broadcast_addressess) == 0 {
		return &LANError{"No broadcast addresses found",nil}
	}

	for _,addr := range broadcast_addressess {
		net.sendpacket(addr,data)
	}
}


