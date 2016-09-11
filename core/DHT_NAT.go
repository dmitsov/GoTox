package core

import (
	"encoding/binary"
	"math/rand"
	"net"
	"time"
)

//func (dht *DHT) sendNATping(publickKey []byte, )

//Get the index of a friend in the friendList
func (dht *DHT) friendIndex(publicKey []byte) int {

	for i := 0; i < len(dht.friendList); i++ {
		if idEqual(dht.friendList[i].publicKey, publicKey) {
			return i
		}
	}

	return -1
}

//
func (dht *DHT) getFriendClientList(friendIndex int) []*net.UDPAddr {
	var friend *DHTFriend = &dht.friendList[friendIndex]
	ipv4sList := make([]*net.UDPAddr, 0)
	ipv6sList := make([]*net.UDPAddr, 0)
	for i := 0; i < len(friend.clientList); i++ {
		var client *ClientData = &friend.clientList[i]
		if idEqual(client.publicKey, friend.publicKey) && (!isTimeout(&client.assoc4.retTimestamp, BadNodeTimeout) || !isTimeout(&client.assoc6.retTimestamp, BadNodeTimeout)) {
			return nil
		}

		if ipIsset(client.assoc4.retIPPort.IP) && !isTimeout(&client.assoc4.retTimestamp, BadNodeTimeout) {
			ipv4sList = append(ipv4sList, client.assoc4.retIPPort)
		}

		if ipIsset(client.assoc6.retIPPort.IP) && !isTimeout(&client.assoc6.retTimestamp, BadNodeTimeout) {
			ipv4sList = append(ipv6sList, client.assoc6.retIPPort)
		}
	}

	var friendIpPortList []net.UDPAddr

	if FriendIpListPad {
		friendIpPortList = ipv6sList
		if len(ipv6sList) < MaxFriendsClient {
			var ipv4Count int
			if MaxFriendClients-len(ipv6sList) > len(ipv4sList) {
				ipv4Count = len(ipv4sList)
			} else {
				ipv4Count = MaxFriendClients - len(ipv6sList)
			}

			friendIpPortList = append(friendIpPortList, ipv4sList[:ipv4Count])
		}
	} else {
		if len(ipv6sList) >= len(ipv4sList) {
			friendIpPortList = ipv6sList
		} else {
			friendIpPortList = ipv4sList
		}
	}

	return friendIpPortList
}

func (dht *DHT) routToFriend(friendId, packet []byte) (int, error) {
	friendIndex = dht.friendIndex(friendId)
	if friendIndex == -1 {
		return 0, &DHTError{"Could not find friend in the friendList"}
	}

	friendIPs := dht.friendList(friendIndex)

	var sentIPs [MaxFriendClients]bool
	var sentNum int

	for i, _ := range friendIPs {
		l, err := dht.net.SendPacket(friendIPs[i], packet)
		if err == null {
			sentNum++
		}
	}

	return sentNum
}

func (dht *DHT) routeOneToFriend(friendId, packet []byte) error {
	var friendIndex int = dht.friendIndex(friendId)

	if friendIndex == -1 {
		return &DHTError{"The specified friendId isn't in the friend list of the node"}
	}

	friend := dht.friendList[friendIndex]

	ipList := make([]net.UDPAddr, 0)

	for a := 0; a < 2; a++ {
		for i := 0; i < MaxFriendClients; i++ {
			client := &friend.clientList[i]
			var assoc *IPPTsPng

			if a == 0 {
				assoc = &client.assoc4
			} else {
				assoc = &client.assoc6
			}

			if isSet(assoc.retIpPort.IP) && !isTimeout(assoc.retTimestamp, BadNodeTimeout) {
				ipList := append(ipList, assoc.retIpPort)
			}
		}
	}

	var listIndex int = rand.Int() % len(ipList)

	if _, err := dht.net.SendPacket(ipList[listIndex], packet); err != nil {
		return &DHTError{"Route one to friend error: " + err.Error()}
	}

	return nil
}

func (dht *DHT) sendNatPing(publickKey []byte, pingId uint64, pingType byte) error {
	data := make([]byte, 9)

	data[0] = pingType
	binary.BigEndian.PutUint64(data[1:], pingId)

	packet, err := createRequest(dht.selfPublickKey, dht.selfSecretKey, publickKey, data, 9, CryptoPacketNatPing)

	if err != nil {
		return &DHTError{"Error in sending a NAT ping: " + err.Error()}
	}

	switch pingType {
	case 0: //packet request for routing to many people
		err = dht.routeToFriend(publickKey, packet)
	case 1: //if packet is response use only one person to route it
		err = dht.routeOneToFriend(publickKey, packet)
	}

	if err != nil {
		return &DHTError{"Error in sending NAT ping: " + err.Error()}
	}

	return nil
}

func (dht *DHT) handleNatPing(source *net.UDPAddr, sourcePublickKey []byte, packet []byte) error {
	if len(packet) != 9 {
		return &DHTError{"Handle NAT ping: packet is of the wrong length"}
	}

	pingId := binary.BigEndian.Uint64(packet[1:])
	friendIndex := dht.friendIndex(sourcePublickKey)
	if friendIndex == -1 {
		return &DHTError{"Handle NAT ping: Ping sent by a none friend"}
	}

	friend := &dht.friendList[friendIndex]

	if packet[0] == NatPingRequest {
		dht.sendNatPing(sourcePublickKey, pingId, NatPingResponse)
		friend.nat.recvNatPingTimestamp = time.Now()
	} else if packet[0] == NatPingResponse {
		if friend.nat.pingId != pingId {
			return &DHTError{"Handle NAT ping: Wrong ping id"}
		}

		friend.nat.pingId = random64b()
		friend.nat.holePunching = true
	}

	return nil
}

func getCommonIP(ipPortList []*net.UDPAddr, minNum int) net.IP {
	ipsCount := make([]int, len(ipPortlist))

	for i, ipPort := range ipPortList {
		for j, _ := range ipPortList {
			if ipPortList[j].Equal(ipPort) {
				ipsCount[i]++
			}

			if ipsCount[i] >= minNum {
				return ipPort.IP
			}
		}
	}

	return net.IPZero
}

func getIpPorts(ipPortList []*net.UDPAddr, ip net.IP) []uint16 {
	ports := make([]uint16, 0)

	for _, ipPort := range ipPortList {
		if ip.Equal(ipPortList) {
			ports = append(ports, ipPort.Port)
		}
	}

	return ports
}

func (dht *DHT) punchHoles(ip net.IP, portList []uint16, friendIndex uint16)
