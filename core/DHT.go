package core

import (
	"encoding/binary"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"net"
	"syscall"
	"binary"
	"time"
)

//Get shared key to encrypt/decrypt DHT packet from public_key into shared_key
//For packets that we receive
func (d *DHT) DHTGetSharedKeyRecv(public_key []byte) ([]byte, error) {
	return d.shared_keys_recv.getSharedKey(d.self_secret_key, public_key)
}

//Get shared key to encrypt/decrypt DHT packet fromt public_key into shared_key
//for packets that we send
func (d *DHT) DHTGetSharedKeySent(public_key []byte) ([]byte, error) {
	return d.shared_keys_sent.getSharedKey(d.self_secret_key, public_key)
}

//helper func: gets the correct friend index
//in the DHT friend list if there is no friend
//with the given public_key return -1
func (d *DHT) friendNum(public_key []byte) int {
	for i, _ := range d.friendList {
		if public_key_cmp(d.friendList[i].public_key, public_key) {
			return i
		}
	}

	return -1
}

/*Find MAX_SENT_NODES nodes closest to the public key
 */
func (d *DHT) getSomewhatCloseNodes(public_key []byte, saFamily byte, isLan bool, wantGood bool) NodeList {
	nodes := make(NodeList, 0)
	nodes = getCloseNodesInner(public_key, nodes, d.close_clientlist, saFamily, isLan, false)

	for i, _ := range d.friendList {
		nodes = getCloseNodesInner(public_key, nodes, d.friendList[i].client_list, saFamily, isLan, false)
	}

	return nodes
}

/* Replace a first bad (or empty) node with this one
 *  or replace a possibly bad node (tests failed or not done yet)
 *  that is further than any other in the list
 *  from the cmpPublicKey
 *  or replace a good node that is further
 *  than any other in the list from the cmpPublicKey
 *  and further than publicKey
 *
 * Do not replace any node if the list has no bad or possibly bad nodes
 *  and all nodes in the list are closer to cmpPublicKey
 *  than publicKey.
 *
 *  returns nill when the item was stored, error otherwise */
func (cl ClientDataList) ReplaceAll(publicKey, cmpPublicKey []byte, ipPort *net.UDPAddr) error {
	if len(ipPort.IP) != net.IPv4len && len(ipPort.IP) != net.IPv6len {
		return &DHTError{"Wrong IP address"}
	}

	if !isOkStoreNode(&cl[0], publicKey, cmpPublickKey) && !isOkStoreNode(&cl[1], publicKey, cmpPublicKey) {
		return &DHTError{"Could not store public key in cliend data list"}
	}

	cl.clientListSort(cmpPublicKey)

	var ipptrWrite, ipptrClear *IPPTsPng

	if len(ipPort.IP) == net.IPv4len {
		ipptrWrite = &cl[0].assoc6
		ipptrClear = &cl[0].assoc4
	} else {
		ipptrWrite = &cl[0].assoc4
		ipptrClear = &cl[0].assoc6
	}

	copy(cl[0].public_key, publicKey)
	ipptrWrite.ip_port = ipPort
	ipptrWrite.timestamp = time.Now().Unix()

	ipReset(ipptrWrite.retIpPort.IP)
	ipptrWrite.RetIpPort.Port = 0
	ipptrWrite.retTimestamp = 0

	return nil
}

func (dht *DHT) CanAddNodeToList(publicKey []byte, ipPort *net.UDPAddr) bool {
	index := bitByBitCmp(publicKey, dht.self_public_key)

	if index > LClientLength {
		index = LClientLength - 1
	}

	for i := 0; i < LClientLength; i++ {
		client := &dht.closeClientList[(index*LClientLength)+i]
		if isTimeout(client.assoc4.timestamp, BadNodeTimeout) && isTimeout(client.assoc6.timestamp, BadNodeTimeout) {
			return true
		}
	}

	return false
}

func (dht *DHT) CanAddNodeToList(publicKey []byte, ipPort *net.UDPAddr) {
	index := bitByBitCmp(publicKey, dht.self_public_key)

	if index > LClientLength {
		index = LClientLength - 1
	}

	for i := 0; i < LClientLength; i++ {
		client := &dht.closeClientList[(index*LClientLength)+i]
		if isTimeout(client.assoc4.timestamp, BadNodeTimeout) && isTimeout(client.assoc6.timestamp, BadNodeTimeout) {
			var ipptrWrite, ipptrClear *IPPTsPng

			if len(ipPort.IP) == net.IPv4len {
				ipptrWrite = &cl[0].assoc6
				ipptrClear = &cl[0].assoc4
			} else {
				ipptrWrite = &cl[0].assoc4
				ipptrClear = &cl[0].assoc6
			}

			copy(cl[0].public_key, publicKey)
			ipptrWrite.ip_port = ipPort
			ipptrWrite.timestamp = time.Now().Unix()

			ipReset(ipptrWrite.retIpPort.IP)
			ipptrWrite.RetIpPort.Port = 0
			ipptrWrite.retTimestamp = 0
		}
	}

}

//Check if the node obtained with GetNodes with publicKey should be pinged
//It should be called after AddToLists. Returns true if it should be pinged
//and false when it shouldn't be pinged
func (dht *DHT) PingNodesFromGetNodes(publicKey []byte, ipPort *net.UDPAddr) bool {
	var retValue bool
	if dht.CanAddNodeToList(publicKey, ipPort) {
		retValue = true
	}

	if retValue && !dht.toBootstrap.ClientInNodeList(publicKey) {
		if len(dht.toBootstrap) < MaxCloseToBootstrapNodes {
			newNode := NodeFormat{publicKey, ipPort}
			dht.toBootstrap = append(dht.toBootsrap, newNode)
		} else {
			dht.ToBootstrap.AddToList(publicKey, ipPort, dht.selfPublicKey)
		}
	}

	for i, _ := range dht.friendsList {
		friend := &dht.friendsList[i]

		ok := friend.clientList[1].StoreNodeOk(publicKey, friend.publicKey) || friend.clientList[0].StoreNodeOk(publicKey, friend.publicKey)

		if ok && !friend.toBootstrap.ClientInNodeList(publicKey) &&
			friend.clientList.isPkInClientList(publicKey, ipPort) {
			if len(friend.toBootstrap) < MaxSentNodes {
				newNode := NodeFormat{publicKey, ipPort}
				friend.toBootstrap = append(dht.toBootsrap, newNode)
			} else {
				friend.toBootstrap.AddToList(publicKey, ipPort, friend.publicKey)
			}

			retValue = true
		}
	}

	return retValue
}

func (dht *DHT) AddToList(publicKey []byte, ipPort *net.UDPAddr) (uint32, error) {
	var used uint32
	if len(ipPort.IP) == net.IPv6len {
		ip4 := ipPort.IP.ToIP4()
		if ip4 != nil {
			ipPort.IP = ip4
		}
	}

	if dht.closeClientList.ClientOrIpPortInList(publicKey, ipPort) {
		if err := dht.AddToClose(publicKey, ipPort); err == nil {
			used++
		}
	} else {
		used++
	}

	var friendFoundIp *DHTFriend

	for i, _ := range dht.friendsList {
		if dht.freindList[i].clientList.ClientOrIpPortInList(publicKey, ipPort) {
			if err := dht.friendList[i].clientList.ReplaceAll(publicKey, ipPort, dht.friendList[i].publicKey); err == nil {
				friend := &dht.friendsList[i]
				if publicKeyCmp(publicKey, friend.publicKey) {
					friendFoundIp = friend
				}

				used
			} else {
				return 0, &DHTError{"Error in adding to dht lists: " + err.Error()}
			}
		} else {
			friend := &dht.friendList[i]
			if publicKeyCmp(publicKey, friend.publicKey) {
				friendFoundIP = friend
			}
			used++
		}
	}

	if friendFoundIp != nil {
		for i, _ := range friendFoundIP.callbacks {
			if friendFoundIp.callbacks[i].ipCallback != nil {
				friendFoundIp.callbacks[i].ipCallback(friendFoundIp.callbacks[i].data, friendFoundIp.callbacks[i].number, ipPort)
			}
		}
	}

	//TODO: finish this part of the code
	if EnableAssocDHT {
		if dht.assoc != nil {
			// have to add some code here for this but I have no idea what to do
		}
	}
	return used
}

/* Updates the friend ips if the returned publicKey is a friend of DHT
 * nodePublicKey is the node that send us the new data
 */
func (dht *DHT) returnedIpPorts(ipPort *net.UDPAddr, publicKey, nodePublicKey []byte) {
	var used bool

	toIpv4(ipPort)
	currentTime := time.Now()

	if idEqual(publicKey, dht.selfPublicKey) {
		for i, _ := range dht.closeClientList {
			if idEqual(publicKey, dht.closeClientList[i].publicKey) {
				if len(ipPort.IP) == net.IPv4len {
					dht.closeClientList[i].assoc4.retIpPort = ipPort
					dht.closeClientList[i].assoc4.retTimestamp = currentTime
				} else if len(ipPort.IP) == net.IPv6len {
					dht.closeClientList[i].assoc6.retIpPort = ipPort
					dht.closeClientList[i].assoc6.retTimestamp = currentTime
				}

				used = true
				break
			}
		}
	} else {
		for i := 0; i < len(dht.friendList) && !used; i++ {
			if idEqual(publicKey, dht.friendList[i].publicKey) {
				for j, _ := range dht.friendList[i].clientList {
					if idEqual(nodePublicKey, dht.friendList[i].clientList[j].publicKey) {
						if len(ipPort.IP) == net.IPv4len {
							dht.closeClientList[i].assoc4.retIpPort = ipPort
							dht.closeClientList[i].assoc4.retTimestamp = currentTime
						} else if len(ipPort.IP) == net.IPv6len {
							dht.closeClientList[i].assoc6.retIpPort = ipPort
							dht.closeClientList[i].assoc6.retTimestamp = currentTime
						}

						used = true
						break
					}
				}
			}
		}
	}

	if EnableAssocDHT {
		if dht.assoc != nil {
			//TODO: write code for this part
		}
	}
}

//helper function for packing sender node in binary format
func packNodeFormat(publicKey []byte, ipPort *net.UDPAddr) []byte {
	plainMessage := make([]byte, NodeFormatSize)

	copy(plainMessage[:cryptobox.CryptoBoxPublicKeyBytes], publicKey)
	if ipPort.IP.IsIPv4() {
		plainMessage[cryptobox.CryptoBoxPublicKeyBytes] = syscall.AF_INET
	} else {
		plainMessage[cryptobox.CryptoBoxPublicKeyBytes] = syscall.AF_INET6
	}

	ip := ipPort.IP.ToIPv6()
	copy(plainMessage[cryptobox.CryptoBoxPublicKeyBytes + 1 : cryptobox.CryptoBoxPublicKeyBytes + 1 + net.IPv6len], ip)
	plainMessage[cryptobox.CryptoBoxPublicKeyBytes + 1 + net.IPv6len] = byte(ipPort.Port & 0x00FF)
	plainMessage[cryptobox.CryptoBoxPublicKeyBytes + 1 + net.IPv6len + 1] = byte((ipPort.Port & 0xFF00) >> 8)
	
	return plainMessage
}

//Send a DHT getnodes request
func (dht *DHT) GetNodes(clientID, publicKey []byte, ipPort *net.UDPAddr, sendbackNode *NodeFormat) error {
	if idEqual(dht.selfPublicKey, publicKey) {
		return &DHTError{"Can't send to getnodes request to self"}	
	}

	plainMessage := packNodeFormat(publicKey, ipPort)
	
	var pingId uint64
	if sendbackNode == nil {
		plainMessage = append(plainMessage, packNodeFormat(sendbackNode.publicKey, sendbackNode.ipPort))
		pingId = dht.dhtHardenPingArray.Add(plainMessage)
	} else {
		pingId = dht.dhtPingArray.Add(plainMessage)
	}
	
	if pingId == 0 {
		return &DHTError {"Couldn't add message to ping array"}
	}	

	message := make([]byte, 36) // the size of the message len(clientId) + 4 bytes of the pingid
	pingIdBytes := make([]byte, 8)
	binary.PutUvariant(pingIdBytes, pingId)
			
	data := make([]byte,1 + cryptobox.CryptoBoxPublicKeyByts + cryptobox.CryptoBoxNonceBytes + len(message) + cryptobox.CryptoBoxMacBytes)
		

	copy(message[:cryptobox.CryptoBoxPublicKeyBytes], clientId)
	copy(message[cryptobox.CryptoBoxPublicKeyBytes:], pingId)
			
	sharedKey := dht.GetSharedKeySent(publicKey)
	
	nonce := new_nonce()	
	
	encryptedData,err := encrypt_data_symmetric(sharedKey, nonce, message)

	if err != nil {
		return &DHTError{ "Error in getnodes: " + err.Error() }
	}

	data[0] = NetPacketGetNodes
	copy(data[1:cryptobox.CryptoBoxPublicKeyBytes], dht.selfPublicKey)
	copy(data[1 + cryptobox.CryptoBoxPublicKeyBytes : 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes], nonce)
	copy(data[1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes:], encryptedData)

	err = dht.net.SendPacket(ipPort, data)	
	if err != nil {
		return &DHTError {"Error in sending getnodes request: " + err.Error()}
	}
	return nil
}

//Send a sendnodes response to IPv6 nodes
func (dht *DHT) SendNodesIPv6(publicKey, clientId []byte, sharedEncryptionKey []byte, sendbackData []byte, ipPort *net.UDPAddr) error {
	if idEqual(dht.selfPublickey, publicKey) {
		return &DHTError{"Can't send a response "}
	}		

	if len(sendbackData) != 8 {
		return &DHTError{"sendbackData should be of length of 8"}
	}

	data := make([]byte, 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes + NodeFormatSize * MaxSentNodes + 8 + cryptobox.CryptoBoxMacBytes)

	nodeList := dht.GetCloseNodes(clientId, 0, isLan(ipPort.IP))
	plain = make([]byte, 1)
	
	nonce := new_nonce()

	var nodeLength int
	if len(nodeList) > 0 {
		packedNodes,err := packNodes(nodeList)	
		if err != nil {
			return &DHTError{"DHT error:" + err.Error()}
		}
		
		if len(packedNodes) == 0 {
			return &DHTError{"DHT error: No nodes to send back"}
		}
		
		plain = append(plain, packedNodes)
	}
	
	plain[0] = len(nodeList)
	plain = append(plain, sendbackData)

	encryptedData := encrypt_data_symmetric(sharedEncryptionKey, nonce, plain)
	
	//now we check to see if the encryption is alright
	if len(encryptedData) != 1 + len(sendbackData) + len(plain) + cryptobox.CryptoBoxMacBytes {
		return &DHTError{"Error in encryption!"}
	}

	data[0] = NetPacketSendNodesIPv6
	copy(data[1 : 1 + cryptobox.CryptoBoxPublicKeyBytes], dht.selfPublicKey)
	copy(data[1 + cryptobox.CryptoBoxPublicKeyBytes : 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes], nonce)
	copy(data[1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes:],encryptedData)

	err := dht.net.SendPacket(ipPort, data)

	if err != nil {
		return &DHTError{"DHT error: " + err.Error()}
	}

	return nil
}

//have to do something for error handling here
func (dht *DHT) handleGetNodes(data []byte, ip net.IP, port uint16){
	if len(data) == 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes + cryptobox.CryptoBoxPublicKeyBytes + 8 
				+ cryptobox.CryptoBoxMacBytes {
		return
	}

	if idEqual(dht.selfPublicKey, data[1 : 1 + cryptobox.CryptoBoxPublicKeyBytes]) {
		return
	}

	sharedKey := dht.getSharedKeyRecv(data[1 : 1 + cryptobox.CryptoBoxPublicKeyBytes])
	
	plainMessage := decrypt_data_symmetric(sharedKey, 
							   data[1 + cryptobox.CryptoBoxPublicKeyBytes : 1 + cryptobox.CryptoBoxPublicKeyBytes + 									cryptobox.CryptoBoxNonceBytes], 
							   data[1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes:])
	
	if len(plainMessage) != cryptobox.CryptoBoxPublicKeyBytes + 8 {
		return
	}

	sourceIPPort := &net.UDPAddr{ip, port}
	
	err := dht.SendNodesIPv6(data[1 : 1 + cryptobox.CryptoBoxPublicKeyBytes], plainMessage[:cryptobox.CryptoBoxPublicKeyBytes], sourceIPPort, sharedKey)
	
	if err != nil {
		return	
	}

	dht.ping.Add(data[1:], sourceIPPort)
}

//possible problems: byte slice to IP might be faulty
func unpackNode(data []byte) *NodeFormat {
	publicKey := data[:cryptobox.CryptoBoxPublicKeyBytes]
	ip := net.IP(data[cryptobox.CryptoBoxPublicKeyBytes + 1: cryptobox.CryptoBoxPublicKeyBytes + 17])

	if data[cryptobox.CryptoBoxPublicKeyBytes] == syscall.AF_INET {
		ip = ip.ToIPv4()
	}

	port := uint16(data[cryptobox.CryptoBoxPublicKeyBytes + 17] | data[cryptobox.CryptoBoxPublicKeyBytes + 18] << 8)
	
	return &NodeFormat{publicKey, &net.UDPAddr{ip, port} }
}

func (dht *DHT) canSendNode(publicKey []byte, ipPort *net.UDPAddr, pingId uint64, sendbackNode *NodeFormat) bool {
	data := dht.pingArray(pingId)
	
	if len(data) == 2 * NodeFormatSize {
		node := unpackNode(data[NodeFormatSize:])
		sendbackNode.ipPort = node.ipPort;
		sendbackNode.publicKey = node.publicKey
	} else if len(data) != NodeFormatSize {
		return false
	}

	test := unpackNode(data)
	if !ipPortEqual(test.ipPort, ipPort) || publicKeyCmp(publicKey, test.publicKey) {
		return false
	}

	return true
}

func (dht *DHT) sendHardeningGetNodeResponse(sendToNode *NodeFormat, queriedClientId []byte, nodesData []byte) error {

	return nil
}

//core handle function for the sendnodes response
func (dht *DHT) handleSendNodesCore(ipPort *net.UDPAddr, data []byte) ([]NodeFormat, error) {
	clientIdSize := 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes + 8 + cryptobox.CryptoBoxMacBytes	

	//needed checks	
	if len(data) < clientIdSize {
		return nil, &DHTError{"Data length is too small"}
	} 

	dataSize := len(data) - clientIdSize
	
	if dataSize == 0 {
		return nil, &DHTError{"There is no data to decrypt"}
	}	

	if dataSize > NodeFormatSize * MaxSendNodes {
		return nil, &DHTError{"The data size is too big"}
	}

	sharedKey := dht.getSharedKeySent(data[1:1 + cryptobox.CryptoBoxPublicKeyBytes])

	plainMessage := decrypt_data_symmetric(sharedKey, data[1 + cryptobox.CryptoBoxPublicKeyBytes: 1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes], data[1 + cryptobox.CryptoBoxPublicKeyBytes + cryptobox.CryptoBoxNonceBytes:])
	
	if len(plainMessage) != dataSize + 1 + 8 {
		return nil, &DHTError{"Wrong size of the decrypted string"}
	}

	var pingIdArray []byte = plainMessage[1 + dataSize : 1 + dataSize + 8]
	var pingId uint64
	for i, v := range pingIdArray {
		pingId |= v << (i * 8)
	}

	sendBackNode := &NodeFormat{}
	
	if !canSendNode(data[1 : 1 + cryptobox.CryptoBoxPublicKeyBytes], ipPort, sendBackNode) {
		return &DHTError{"Can't get sendback node"}
	}

	plainNodes := unpackNodes(plainMessage[1:], plainMessage[0], dataSize)
	
	if len(plainNodes) * NodeFormatSize != dataSize || plainMessage[0] != len(plainNodes) {
		return &DHTError{"Wrong number of nodes"}
	}

	dht.AddToList(ipPort, data[1: 1 + cryptobox.CryptoBoxPublicKeyBytes])
	
	dht.sendHardeningGetNodeRes(sendBackNode, data[1: 1 + cryptobox.CryptoBoxPublicKeyBytes])

	return plainNodes, nil
}

//handle sendnodes response 
func (dht *DHT) handleSendNodesIPv6(data []byte, ipPort *net.UDPAddr) {
	plainNodes,err := handleSendNodesCore(ipPort, data)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if len(plainNodes) {
		return
	}

	for i, _ := range plainNodes {
		if ipPortIsSet(plainNodes[i].ipPort {
			dht.pingNodeFromGetNodesOk(plainNodes[i].publicKey, plainNodes[i].ipPort)
			dht.returnedIpPorts(plainNodes[i].ipPort, plainNodes[i].publicKey, data[1: 1 + cryptobox.CryptoBoxPublicKeyBytes])
		}
	}
}

