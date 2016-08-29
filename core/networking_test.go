package core

import (
	"net"
	"testing"
	//	"os"
	"fmt"
	"time"
)

//some simple tests to see if I did everythin right

func TestMonotonicTime(t *testing.T) {
	t.Parallel()
	InitiateMonotonicTime()
	time.Sleep(time.Millisecond)
	timeMon := GetTimeMonotonic()
	fmt.Println("Time passed: ", timeMon)
	if timeMon != 1 {
		t.Fail()
	}
}

func TestSetReuseAddr(t *testing.T) {
	t.Parallel()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:7070")
	if err != nil {
		t.Error("TestSetReuseAddr: " + err.Error())
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	defer conn.Close()
	if err != nil {
		t.Error("TestSetReuseAddr" + err.Error())
		return
	}
	f, err := conn.File()
	if err != nil {
		t.Error("Couldn't get file")
		return
	}
	defer f.Close()
	sock := int(f.Fd())
	if err = SetSocketReuseaddr(sock); err != nil {
		t.Error("TestSetReuseAddr " + err.Error())
		return
	}
}

func TestSetDualStack(t *testing.T) {
	t.Skip()
	ip := net.ParseIP("::1")
	udpAddr := new(net.UDPAddr)
	udpAddr.IP = ip
	udpAddr.Port = 4444

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Error("TestSetDualStack: " + err.Error())
		return
	}
	defer conn.Close()
	f, err := conn.File()
	if err != nil {
		t.Error(err.Error())
		return
	}
	defer f.Close()
	sock := int(f.Fd())
	fmt.Println("Listen socket")
	if err = SetDualStack(sock); err != nil {
		t.Error("TestSetDualStack: " + err.Error())
		return
	}
}

func TestNetworkingInitIPv4(t *testing.T) {
	t.Parallel()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Error(err.Error())
		return
	}

	for _, adr := range addresses {
		ip, _, err := net.ParseCIDR(adr.String())
		ip = ip.To4()
		if ip == nil {
			continue
		}
		networkingCore, err := InitNetworking(ip, 5050)
		if err != nil || networkingCore == nil {
			//	fmt.Println("Error: ", err.Error())
			//	t.Fail()
			continue
		}
		if networkingCore != nil {
			return
		}
		networkingCore.Kill()
	}

	t.Fail()
}

func TestNetworkingSend(t *testing.T) {
	t.Parallel()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Error(err.Error())
		return
	}

	var networkingCore *Networking_Core
	var ip net.IP
	for _, adr := range addresses {
		ip, _, err = net.ParseCIDR(adr.String())
		ip = ip.To4()
		if ip == nil {
			continue
		}
		networkingCore, err = InitNetworking(ip, 8000)
		if err != nil || networkingCore == nil {
			//	fmt.Println("Error: ", err.Error())
			//	t.Fail()
			continue
		}
		if networkingCore != nil {
			break
		}

	}
	if networkingCore == nil {
		t.Error("Can't initialize networking core")
		return
	}

	defer networkingCore.Kill()
	msg := "Hello, buddy!"
	sync := make(chan struct{})

	udpAddr := new(net.UDPAddr)
	udpAddr.IP = ip
	udpAddr.Port = 9900
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Error(err.Error())
		return
	}
	defer udpListener.Close()

	go func() {
		defer func() {
			fmt.Println("Read function finished")
			sync <- struct{}{}
		}()
		recvData := make([]byte, len(msg))
		fmt.Println("Listening udp port on ip:"+ip.String()+" Port:", 9900)
		n, sendAddr, err := udpListener.ReadFromUDP(recvData)
		fmt.Println("Data read")
		if err != nil {
			t.Error(err.Error())
			return
		}

		recvData = recvData[:n]
		if string(recvData) != msg {
			fmt.Println(string(recvData))
			t.Fail()
			return
		}
		fmt.Println("Send address: ", sendAddr)

	}()

	data := make([]byte, 0)
	data = append(data, []byte(msg)...)
	fmt.Println("Sending packet")
	err = networkingCore.SendPacket(ip, 9900, data)
	fmt.Println("Packet was sent")
	if err != nil {
		t.Error(err.Error())
		return
	}
	<-sync
	fmt.Println("Everything finished")
}

func TestNetworkingReceive(t *testing.T) {
	//t.Parallel()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Error(err.Error())
		return
	}

	var networkingCore *Networking_Core
	var ip net.IP
	for _, adr := range addresses {
		ip, _, err = net.ParseCIDR(adr.String())
		ip = ip.To4()
		if ip == nil {
			continue
		}
		networkingCore, err = InitNetworking(ip, 8000)
		if err != nil || networkingCore == nil {
			//	fmt.Println("Error: ", err.Error())
			//	t.Fail()
			continue
		}
		if networkingCore != nil {
			break
		}

	}
	if networkingCore == nil {
		t.Error("Can't initialize networking core")
		return
	}

	defer networkingCore.Kill()
	fmt.Println("Starting networking poll")
	go networkingCore.Poll()
	fmt.Println("Networking poll initialized")

	sync := make(chan struct{})

	msg := "Test message!"

	msgHandler := func(data []byte, ip net.IP, port uint16) {
		fmt.Printf("Msg: %s, IP: %s, Port: %d\n", string(data), ip, port)
		if string(data) != msg {
			t.Fail()
			sync <- struct{}{}
			return
		}

		sync <- struct{}{}
	}

	networkingCore.AddHandler(1, msgHandler)

	sendUdpAddr := &net.UDPAddr{ip, int(networkingCore.port), ""}
	recvUdpAddr := &net.UDPAddr{ip, 10000, ""}
	udpSender, err := net.DialUDP("udp", recvUdpAddr, sendUdpAddr)
	if err != nil {
		t.Error(err)
		return
	}
	defer udpSender.Close()
	data := make([]byte, 1)
	data[0] = 1
	data = append(data, []byte(msg)...)

	_, err = udpSender.Write(data)
	if err != nil {
		t.Error(err)
	}
	<-sync
	fmt.Println("Finished networking receive")
}

func TestNetworingInitIPv6(t *testing.T) {
	t.Skip()
	ip := net.ParseIP("fe80::466d:57ff:fe3b:327f")
	networkingCore, err := InitNetworking(ip, 9955)
	if err != nil || networkingCore == nil {
		fmt.Println("Error: ", err.Error())
		t.Fail()
	}
	networkingCore.Kill()

}
