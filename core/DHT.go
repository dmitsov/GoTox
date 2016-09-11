package core

import (
	"encoding/binary"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"net"
	"syscall"
	"time"
)

//Get shared key to encrypt/decrypt DHT packet from public_key into shared_key
//For packets that we receive
func (d *DHT) DHTGetSharedKeyRecv(publicKey []byte) ([]byte, error) {
	return d.sharedKeysRecv.GetSharedKey(d.selfSecretKey, publicKey)
}

//Get shared key to encrypt/decrypt DHT packet fromt public_key into shared_key
//for packets that we send
func (d *DHT) DHTGetSharedKeySent(publicKey []byte) ([]byte, error) {
	return d.sharedKeysSent.GetSharedKey(d.selfSecretKey, publicKey)
}

//helper func: gets the correct friend index
//in the DHT friend list if there is no friend
//with the given public_key return -1
func (d *DHT) friendNum(publicKey []byte) int {
	for i, _ := range d.friendList {
		if publicKeyCmp(d.friendList[i].publicKey, publicKey) {
			return i
		}
	}

	return -1
}

/*Find MAX_SENT_NODES nodes closest to the public key
 */
func (d *DHT) getSomewhatCloseNodes(public_key []byte, saFamily byte, isLan bool, wantGood bool) NodeList {
	nodes := make(NodeList, 0)
	nodes = getCloseNodesInner(public_key, nodes, d.closeClientList, saFamily, isLan, false)

	for i, _ := range d.friendList {
		nodes = getCloseNodesInner(public_key, nodes, d.friendList[i].clientList, saFamily, isLan, false)
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
func (cl ClientDataList) ReplaceAll(publicKey, cmpPublickKey []byte, ipPort *net.UDPAddr) error {
	if len(ipPort.IP) != net.IPv4len && len(ipPort.IP) != net.IPv6len {
		return &DHTError{"Wrong IP address"}
	}

	if !cl[0].isStoreNodeOk(publicKey, cmpPublickKey) && !cl[1].isStoreNodeOk(publicKey, cmpPublickKey) {
		return &DHTError{"Could not store public key in cliend data list"}
	}

	cl.clientListSort(cmpPublickKey)

	var ipptrWrite, ipptrClear *IPPTsPng

	if len(ipPort.IP) == net.IPv4len {
		ipptrWrite = &cl[0].assoc6
		ipptrClear = &cl[0].assoc4
	} else {
		ipptrWrite = &cl[0].assoc4
		ipptrClear = &cl[0].assoc6
	}

	copy(cl[0].publicKey, publicKey)
	ipptrWrite.ipPort = ipPort
	ipptrWrite.timestamp = time.Now()

	ipReset(ipptrWrite.retIPPort.IP)
	ipptrWrite.retIPPort.Port = 0
	ipptrWrite.retTimestamp = time.Unix(0, 0)

	return nil
}

func (dht *DHT) addToClose(publicKey []byte, ipPort *net.UDPAddr) error {
	index := bitByBitCmp(publicKey, dht.selfPublicKey)

	if index > LClientLength {
		index = LClientLength - 1
	}

	for i := 0; i < LClientLength; i++ {
		client := &dht.closeClientList[(index*LClientLength)+i]
		if isTimeout(&client.assoc4.timestamp, BadNodeTimeout) && isTimeout(&client.assoc6.timestamp, BadNodeTimeout) {
			var ipptrWrite *IPPTsPng
			var ipptrClear *IPPTsPng

			if ipPort.IP.To4() != nil {
				ipptrWrite = &client.assoc4
				ipptrClear = &client.assoc6
			} else {
				ipptrWrite = &client.assoc6
				ipptrClear = &client.assoc4
			}

			copy(client.publicKey, publicKey)
			ipptrWrite.ipPort = ipPort
			ipptrWrite.timestamp = time.Now()
			ipptrWrite.retIPPort = &net.UDPAddr{net.IPv6zero, 0, ""}
			ipptrWrite.retTimestamp = time.Unix(0, 0)

			ipptrClear.ipPort = &net.UDPAddr{net.IPv6zero, 0, ""}
			ipptrWrite.timestamp = time.Unix(0, 0)
			ipptrWrite.retIPPort = &net.UDPAddr{net.IPv6zero, 0, ""}
			ipptrWrite.retTimestamp = time.Unix(0, 0)

			return nil
		}
	}

	return &DHTError{"addToClose error: Could not find client with the specified id"}
}

func (dht *DHT) CanAddNodeToList(publicKey []byte, ipPort *net.UDPAddr) bool {
	index := bitByBitCmp(publicKey, dht.selfPublicKey)

	if index > LClientLength {
		index = LClientLength - 1
	}

	for i := 0; i < LClientLength; i++ {
		client := &dht.closeClientList[(index*LClientLength)+i]
		if isTimeout(&client.assoc4.timestamp, BadNodeTimeout) && isTimeout(&client.assoc6.timestamp, BadNodeTimeout) {
			return true
		}
	}

	return false
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
			dht.toBootstrap = append(dht.toBootstrap, newNode)
		} else {
			dht.toBootstrap.addToList(publicKey, ipPort, dht.selfPublicKey)
		}
	}

	for i, _ := range dht.friendList {
		friend := &dht.friendList[i]

		ok := friend.clientList[1].isStoreNodeOk(publicKey, friend.publicKey) || friend.clientList[0].isStoreNodeOk(publicKey, friend.publicKey)

		if ok && !friend.toBootstrap.ClientInNodeList(publicKey) {
			if len(friend.toBootstrap) < MaxSendNodes {
				newNode := NodeFormat{publicKey, ipPort}
				friend.toBootstrap = append(dht.toBootstrap, newNode)
			} else {
				friend.toBootstrap.addToList(publicKey, ipPort, friend.publicKey)
			}

			retValue = true
		}
	}

	return retValue
}

func (dht *DHT) AddToList(publicKey []byte, ipPort *net.UDPAddr) (uint32, error) {
	var used uint32
	if len(ipPort.IP) == net.IPv6len {
		ip4 := ipPort.IP.To4()
		if ip4 != nil {
			ipPort.IP = ip4
		}
	}

	if dht.closeClientList.ClientOrIPPortInList(publicKey, ipPort) {
		if err := dht.addToClose(publicKey, ipPort); err == nil {
			used++
		}
	} else {
		used++
	}

	var friendFoundIp *DHTFriend

	for i, _ := range dht.friendList {
		if dht.friendList[i].clientList.ClientOrIPPortInList(publicKey, ipPort) {
			if err := dht.friendList[i].clientList.ReplaceAll(publicKey, dht.friendList[i].publicKey, ipPort); err == nil {
				friend := &dht.friendList[i]
				if publicKeyCmp(publicKey, friend.publicKey) {
					friendFoundIp = friend
				}

				used++
			} else {
				return 0, &DHTError{"Error in adding to dht lists: " + err.Error()}
			}
		} else {
			friend := &dht.friendList[i]
			if publicKeyCmp(publicKey, friend.publicKey) {
				friendFoundIp = friend
			}
			used++
		}
	}

	if friendFoundIp != nil {
		for i, _ := range friendFoundIp.callbacks {
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
	return used, nil
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
					dht.closeClientList[i].assoc4.retIPPort = ipPort
					dht.closeClientList[i].assoc4.retTimestamp = currentTime
				} else if len(ipPort.IP) == net.IPv6len {
					dht.closeClientList[i].assoc6.retIPPort = ipPort
				}
				dht.closeClientList[i].assoc6.retTimestamp = currentTime

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
							dht.closeClientList[i].assoc4.retIPPort = ipPort
							dht.closeClientList[i].assoc4.retTimestamp = currentTime
						} else if len(ipPort.IP) == net.IPv6len {
							dht.closeClientList[i].assoc6.retIPPort = ipPort
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

	copy(plainMessage[:cryptobox.CryptoBoxPublicKeyBytes()], publicKey)
	if IsIPv4(ipPort.IP) {
		plainMessage[cryptobox.CryptoBoxPublicKeyBytes()] = syscall.AF_INET
	} else {
		plainMessage[cryptobox.CryptoBoxPublicKeyBytes()] = syscall.AF_INET6
	}

	ip := ipPort.IP.To16()
	copy(plainMessage[cryptobox.CryptoBoxPublicKeyBytes()+1:cryptobox.CryptoBoxPublicKeyBytes()+1+net.IPv6len], ip)
	plainMessage[cryptobox.CryptoBoxPublicKeyBytes()+1+net.IPv6len] = byte(ipPort.Port & 0x00FF)
	plainMessage[cryptobox.CryptoBoxPublicKeyBytes()+1+net.IPv6len+1] = byte((ipPort.Port & 0xFF00) >> 8)

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
		plainMessage = append(plainMessage, packNodeFormat(sendbackNode.publicKey, sendbackNode.ipPort)...)
		pingId = dht.hardenPingArray.Add(plainMessage)
	} else {
		pingId = dht.pingArray.Add(plainMessage)
	}

	if pingId == 0 {
		return &DHTError{"Couldn't add message to ping array"}
	}

	message := make([]byte, 36) // the size of the message len(clientId) + 4 bytes of the pingid
	pingIdBytes := make([]byte, 8)
	binary.PutUvarint(pingIdBytes, pingId)

	data := make([]byte, 1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()+len(message)+cryptobox.CryptoBoxMacBytes())

	copy(message[:cryptobox.CryptoBoxPublicKeyBytes()], clientID)
	copy(message[cryptobox.CryptoBoxPublicKeyBytes():], pingIdBytes)

	sharedKey, err := dht.sharedKeysSent.GetSharedKey(publicKey, nil)
	if err != nil {
		return &DHTError{"Error in GetNodes: " + err.Error()}
	}

	nonce := new_nonce()

	encryptedData, err := encrypt_data_symmetric(sharedKey, nonce, message)

	if err != nil {
		return &DHTError{"Error in getnodes: " + err.Error()}
	}

	data[0] = NetPacketGetNodes
	copy(data[1:cryptobox.CryptoBoxPublicKeyBytes()], dht.selfPublicKey)
	copy(data[1+cryptobox.CryptoBoxPublicKeyBytes():1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()], nonce)
	copy(data[1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes():], encryptedData)

	err = dht.net.SendPacket(ipPort.IP, uint16(ipPort.Port), data)
	if err != nil {
		return &DHTError{"Error in sending getnodes request: " + err.Error()}
	}
	return nil
}

//Send a sendnodes response to IPv6 nodes
func (dht *DHT) SendNodesIPv6(publicKey, clientId []byte, sharedEncryptionKey []byte, sendbackData []byte, ipPort *net.UDPAddr) error {
	if idEqual(dht.selfPublicKey, publicKey) {
		return &DHTError{"Can't send a response "}
	}

	if len(sendbackData) != 8 {
		return &DHTError{"sendbackData should be of length of 8"}
	}

	data := make([]byte, 1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()+NodeFormatSize*MaxSendNodes+8+cryptobox.CryptoBoxMacBytes())

	nodeList := dht.GetCloseNodes(clientId, 0, IsLAN(ipPort.IP))
	plain := make([]byte, 1)

	nonce := new_nonce()

	var nodeLength int
	if len(nodeList) > 0 {
		packedNodes, err := packNodes(nodeList)
		if err != nil {
			return &DHTError{"DHT error:" + err.Error()}
		}

		if len(packedNodes) == 0 {
			return &DHTError{"DHT error: No nodes to send back"}
		}

		plain = append(plain, packedNodes...)
	}

	plain[0] = len(nodeList)
	plain = append(plain, sendbackData...)

	encryptedData, err := encrypt_data_symmetric(sharedEncryptionKey, nonce, plain)

	//now we check to see if the encryption is alright
	if len(encryptedData) != 1+len(sendbackData)+len(plain)+cryptobox.CryptoBoxMacBytes() || err != nil {
		var errMsg string
		if err != nil {
			errMsg = err.Error()
		}

		return &DHTError{"Error in encryption! " + errMsg}
	}

	data[0] = NetPacketSendNodesIPv6
	copy(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], dht.selfPublicKey)
	copy(data[1+cryptobox.CryptoBoxPublicKeyBytes():1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()], nonce)
	copy(data[1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes():], encryptedData)

	err = dht.net.SendPacket(ipPort.IP, uint16(ipPort.Port), data)

	if err != nil {
		return &DHTError{"DHT error: " + err.Error()}
	}

	return nil
}

//have to do something for error handling here
func (dht *DHT) handleGetNodes(data []byte, ip net.IP, port uint16) {
	if len(data) == 1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()+cryptobox.CryptoBoxPublicKeyBytes()+8+cryptobox.CryptoBoxMacBytes() {
		return
	}

	if idEqual(dht.selfPublicKey, data[1:1+cryptobox.CryptoBoxPublicKeyBytes()]) {
		return
	}

	sharedKey, err := dht.sharedKeysRecv.GetSharedKey(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], nil)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	plainMessage, err := decrypt_data_symmetric(sharedKey,
		data[1+cryptobox.CryptoBoxPublicKeyBytes():1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()],
		data[1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes():])

	if len(plainMessage) != cryptobox.CryptoBoxPublicKeyBytes()+8 || err != nil {
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("Wrong line ")
		}
		return
	}

	sourceIPPort := &net.UDPAddr{ip, int(port), ""}

	err = dht.SendNodesIPv6(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], plainMessage[:cryptobox.CryptoBoxPublicKeyBytes()], plainMessage[cryptobox.CryptoBoxPublicKeyBytes():cryptobox.CryptoBoxPublicKeyBytes()+8], sharedKey, sourceIPPort)

	if err != nil {
		return
	}

	dht.ping.Add(data[1:], sourceIPPort)
}

//possible problems: byte slice to IP might be faulty
func unpackNode(data []byte) *NodeFormat {
	publicKey := data[:cryptobox.CryptoBoxPublicKeyBytes()]
	ip := net.IP(data[cryptobox.CryptoBoxPublicKeyBytes()+1 : cryptobox.CryptoBoxPublicKeyBytes()+17])

	if data[cryptobox.CryptoBoxPublicKeyBytes()] == syscall.AF_INET {
		ip = ip.To4()
	}

	port := uint16(data[cryptobox.CryptoBoxPublicKeyBytes()+17] | data[cryptobox.CryptoBoxPublicKeyBytes()+18]<<8)

	return &NodeFormat{publicKey, &net.UDPAddr{ip, int(port), ""}}
}

func (dht *DHT) canSendNode(publicKey []byte, ipPort *net.UDPAddr, pingId uint64, sendbackNode *NodeFormat) bool {

	data := make([]byte, 2*NodeFormatSize)

	n, err := dht.pingArray.Check(data, pingId)
	if err != nil {
		fmt.Println(err.Error())
		return false
	}

	if n == 2*NodeFormatSize {
		node := unpackNode(data[NodeFormatSize:])
		sendbackNode.ipPort = node.ipPort
		sendbackNode.publicKey = node.publicKey
	} else if n != NodeFormatSize {
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
	clientIdSize := 1 + cryptobox.CryptoBoxPublicKeyBytes() + cryptobox.CryptoBoxNonceBytes() + 8 + cryptobox.CryptoBoxMacBytes()

	//needed checks
	if len(data) < clientIdSize {
		return nil, &DHTError{"Data length is too small"}
	}

	dataSize := len(data) - clientIdSize

	if dataSize == 0 {
		return nil, &DHTError{"There is no data to decrypt"}
	}

	if dataSize > NodeFormatSize*MaxSendNodes {
		return nil, &DHTError{"The data size is too big"}
	}

	sharedKey, err := dht.sharedKeysSent.GetSharedKey(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], nil)

	if err != nil {

		return nil, &DHTError{"Error in handleSendNodesCore: " + err.Error()}
	}

	plainMessage, err := decrypt_data_symmetric(sharedKey, data[1+cryptobox.CryptoBoxPublicKeyBytes():1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes()], data[1+cryptobox.CryptoBoxPublicKeyBytes()+cryptobox.CryptoBoxNonceBytes():])

	if err != nil {
		return nil, &DHTError{"Error in handleSendNodesCore: " + err.Error()}
	}

	if len(plainMessage) != dataSize+1+8 {
		return nil, &DHTError{"Wrong size of the decrypted string"}
	}

	var pingIdArray []byte = plainMessage[1+dataSize : 1+dataSize+8]
	var pingId uint64
	for i, v := range pingIdArray {
		pingId |= uint64(v << uint32(i*8))
	}

	sendBackNode := &NodeFormat{}

	if !dht.canSendNode(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], ipPort, pingId, sendBackNode) {
		return nil, &DHTError{"Can't get sendback node"}
	}

	plainNodes, err := unpackNodes(plainMessage)

	if err != nil {
		return nil, &DHTError{"Error in handleSendNodesCore: " + err.Error()}
	}

	if len(plainNodes)*NodeFormatSize != dataSize || int(plainMessage[0]) != len(plainNodes) {
		return nil, &DHTError{"Wrong number of nodes"}
	}

	dht.AddToList(data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], ipPort)

	dht.sendHardeningGetNodeResponse(sendBackNode, data[1:1+cryptobox.CryptoBoxPublicKeyBytes()], nil)

	return plainNodes, nil
}

//handle sendnodes response
func (dht *DHT) handleSendNodesIPv6(data []byte, ipPort *net.UDPAddr) {
	plainNodes, err := dht.handleSendNodesCore(ipPort, data)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if len(plainNodes) == 0 {
		return
	}

	for i, _ := range plainNodes {
		if ipPortIsSet(plainNodes[i].ipPort) {
			dht.pingNodeFromGetNodesOk(plainNodes[i].publicKey, plainNodes[i].ipPort)
			dht.returnedIpPorts(plainNodes[i].ipPort, plainNodes[i].publicKey, data[1:1+cryptobox.CryptoBoxPublicKeyBytes()])
		}
	}
}
