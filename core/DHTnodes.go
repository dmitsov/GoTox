package core

import (
	"encoding/binary"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"net"
)

//Function for packing nodes in network format. Used
//to serealize nodes in binary format in order send
//a get_nodes response
func packNodes(nodes []NodeFormat) ([]byte, error) {
	var data []byte = make([]byte, 0)

	for i, _ := range nodes {
		var net_family byte
		//have to be carefull with ip addresses
		//they are usually transformed to ibv6 format
		//for convenieny. Right now it's a hindrance
		switch {
		//family of the returned addresses. It's better to use
		//tox specific constants for the job than sa_family macros
		case len(nodes[i].ip_port.IP) == 4:
			net_family = TOX_AF_INET
		case len(nodes[i].ip_port.IP) == 16:
			net_family = TOX_AF_INET6
		default:
			return nil, &DHTError{"Wrong ip type in nodes!" + fmt.Sprintf("%v", nodes[i].ip_port.IP)}
		}

		//binary serializing
		packedNode := make([]byte, 1)
		port := make([]byte, 2)
		binary.LittleEndian.PutUint16(port, uint16(nodes[i].ip_port.Port))

		packedNode[0] = net_family
		packedNode = append(packedNode, nodes[i].ip_port.IP...)
		packedNode = append(packedNode, port...)
		packedNode = append(packedNode, nodes[i].public_key...)

		data = append(data, packedNode...)
	}

	return data, nil
}

//function for unpacking nodes. Unpacks the received
//nodes in binary format and returns a slice containing
//the returned nodes
func unpackNodes(data []byte) ([]NodeFormat, error) {
	var len_processed uint32
	var nodes []NodeFormat = make([]NodeFormat, 0)

	for len_processed < uint32(len(data)) {
		var ipSize int
		var size uint32
		switch {
		case data[len_processed] == TOX_AF_INET:
			ipSize = net.IPv4len
			size = PackedNodeSizeIP4
		case data[len_processed] == TOX_AF_INET6:
			size = PackedNodeSizeIP6
			ipSize = net.IPv6len
		default:
			return nil, &DHTError{"Wrong ip family type: " + fmt.Sprintf("%d", data[len_processed])}
		}

		if len_processed+size > uint32(len(data)) {
			return nil, &DHTError{"Node size overflowing data len"}
		}

		var node NodeFormat
		node.ip_port = &net.UDPAddr{}
		node.public_key = make([]byte, cryptobox.CryptoBoxPublicKeyBytes())

		//here we're checking to see if the node fits in the remaining byte data

		node.ip_port.IP = make([]byte, ipSize)
		port := binary.LittleEndian.Uint16(data[len_processed+1+net.IPv4len : len_processed+1+uint32(ipSize)+2])

		copy(node.ip_port.IP, data[len_processed+1:len_processed+1+uint32(ipSize)])
		node.ip_port.Port = int(port)
		copy(node.public_key, data[len_processed+1+net.IPv4len+2:len_processed+1+net.IPv4len+2+uint32(cryptobox.CryptoBoxPublicKeyBytes())])
		nodes = append(nodes, node)

		len_processed += size
	}

	return nodes, nil
}

//Returns true if there is a node in the with the same public_key
//in the nodeList
func (n NodeList) ClientInNodeList(public_key []byte) bool {
	for i, _ := range n {
		if public_key_cmp(n[i].public_key, public_key) {
			return true
		}
	}

	return false
}

//function for adding a node to a specific nodeList
func (n NodeList) addToList(public_key []byte, addr *net.UDPAddr, cmp_pk []byte) {
	pk_backup := make([]byte, cryptobox.CryptoBoxPublicKeyBytes())
	var addrBackup *net.UDPAddr

	for i, _ := range n {
		if len(id_closest(cmp_pk, n[i].public_key, public_key)) == 2 {
			copy(pk_backup, n[i].public_key)
			addrBackup = n[i].ip_port
			copy(n[i].public_key, public_key)
			n[i].ip_port = addr
			if i != len(n)-1 {
				n.addToList(pk_backup, addrBackup, cmp_pk)
			}
			return
		}
	}
}

//a helper function for GetCloseNodes
//what it does is fill the the nodelist with the closest nodes
//not counting those that are in the LAN
func getCloseNodesInner(public_key []byte, nodes NodeList, clients ClientDataList, saFamily byte, isLan, wantGood bool) NodeList {

	if saFamily != syscall.AF_INET && saFamily != syscall.AF_INET6 && saFamily != 0 {
		return nil
	}

	for _, c := range clients {
		if nodes.ClientInNodeList(c.public_key) {
			continue
		}

		var ipptp *IPPTsPng

		//we look for the correct IPPTsPng
		if saFamily == syscall.AF_INET {
			ipptp = &c.assoc4
		} else if saFamily == syscall.AF_INET6 {
			ipptp = &c.assoc6
		} else {
			if c.assoc4.timestamp.After(c.assoc6.timestamp) {
				ipptp = &c.assoc4
			} else {
				ipptp = &c.assoc6
			}
		}

		if isTimeout(&ipptp.timestamp, BadNodeTimeout) || // node possibly not working
			(IsLAN(ipptp.ip_port.IP) && !isLan) || // don't send LAN ips to non lan peers
			(!IsLAN(ipptp.ip_port.IP) && wantGood &&
				ipptp.hardening.Correct() != HardeningAllOk && public_key_cmp(public_key, c.public_key)) /* hardening not successfull */ {
			continue
		}

		if len(nodes) < MaxSentNodes {
			node := NodeFormat{}
			copy(node.public_key, c.public_key)
			node.ip_port = ipptp.ip_port
			nodes = append(nodes, node)
		} else {
			nodes.addToList(c.public_key, ipptp.ip_port, public_key)
		}

	}

	return nodes
}
