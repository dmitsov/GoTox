package core

import (
	"net"
	"time"
)

/* This method returns an ip_port for a given public key or a public key for a given ip_port pair.
*  Used for conveniency.
 */
func (list ClientDataList) ClientOrIPPortInList(public_key []byte, ip_port *net.UDPAddr) bool { //TODO: split it in the future. This looks way too clunky for good use
	for i, _ := range list {
		if public_key_cmp(list[i].public_key, public_key) {
			if len(ip_port.IP) == net.IPv4len {
				list[i].assoc4.ip_port.IP = make([]byte, net.IPv4len)
				copy(list[i].assoc4.ip_port.IP, ip_port.IP)
				list[i].assoc4.ip_port.Port = ip_port.Port
				list[i].assoc4.timestamp = time.Now()
			} else if len(ip_port.IP) == net.IPv6len {
				list[i].assoc6.ip_port.IP = make([]byte, net.IPv6len)
				copy(list[i].assoc6.ip_port.IP, ip_port.IP)
				list[i].assoc6.ip_port.Port = ip_port.Port
				list[i].assoc6.timestamp = time.Now()
			}

			return true
		}
	}

	for i, _ := range list {
		if len(ip_port.IP) == net.IPv4len && ipportEqual(list[i].assoc4.ip_port, ip_port) {
			list[i].assoc4.timestamp = time.Now()
			copy(public_key, list[i].public_key)
			list[i].assoc6 = IPPTsPng{}
			return true
		} else if len(ip_port.IP) == net.IPv6len && ipportEqual(list[i].assoc6.ip_port, ip_port) {
			list[i].assoc6.timestamp = time.Now()
			copy(public_key, list[i].public_key)
			list[i].assoc4 = IPPTsPng{}
			return true
		}
	}

	return false
}

//compare two DHT client data entries
func compareClientEntries(e1, e2 ClientData, cmpPublicKey []byte) int {

	b1 := isTimeout(e1.assoc4.timestamp, BadNodeTimeout) && isTimeout(e1.assoc6.timestamp, BadNodeTimeout)
	b2 := isTimeout(e2.assoc4.timestamp, BadNodeTimeout) && isTimeout(e2.assoc6.timestamp, BadNodeTimeout)

	if b1 && b2 {
		return 0
	}

	if b1 {
		return -1
	}

	if b2 {
		return 1
	}

	t1 := hardeningCorrect(e1.assoc4.hardening) != HardeningAllOk &&
		hardeningCorrect(e1.assoc6.hardening) != HardeningALlOk
	t2 := hardeningCorrect(e2.assoc4.hardening) != HardeningAllOk &&
		hardeningCorrect(e2.assoc6.hardening) != HardeningAllOk

	if t1 != t2 {
		if t1 {
			return -1
		}

		if t2 {
			return 1
		}
	}

	closest = idClosest(cmpPublicKey, e1.public_key, e2.public_key)

	if closest == 1 {
		return -1
	}

	if closest == 2 {
		return 1
	}

	return 0
}

func (clientData *ClientData) isStoreNodeOk(public_key, cmp_publicKey []byte) bool {
	if (isTimeout(clientData.assoc4.timestamp, BadNodeTimeout) && isTimeout(clientData.assoc6.timestamp, BadNodeTimeout)) ||
		idClosest(cmp_publicKey, clientData.public_key, public_key) == 2 {
		return true
	} else {
		return false
	}

}

func (cl ClientDataList) clientListInsertSort(cmp_key []byte) {
	//have to implement binary insertion sort
	if len(cl) < 2 {
		return
	}

	for i := 1; i < len(cl); i++ {
		var l, r int = 0, i - 1
		m := l + (r-l)/2
		temp := &cl[i]
		for l < r {
			comp := CompareClientEntries(temp, &cl[m], cmp_key)
			if comp == -1 {
				r = m
			} else if comp == 1 {
				l = m + 1
			} else {
				break
			}
			m = l + (r-l)/2
		}

		if m == i {
			continue
		}
		x := *temp
		for j := i - 1; j >= m; j-- {
			cl[j+1] = cl[j]
		}

		cl[m] = x
	}

}

func merge(c1, c2 ClientDataList, cmp_key []byte) ClientDataList {
	minLength := min(len(c1), len(c2))
	mergedList := make(ClientDataList, 0)

	for i, j := 0, 0; i < minLength && j < minLength; {
		cmp := CompareClientEntries(&c1[i], &c2[j], cmp_key)
		if cmp <= 0 {
			mergedList = append(mergedList, c1[i])
			i++
		} else {
			mergedList = append(mergedList, c2[j])
			j++
		}
	}

	if i < len(c1) {
		for ; i < len(c1); i++ {
			mergedList = append(mergedList, c1[i])
		}
	} else if j < len(c2) {
		for ; j < len(c2); j++ {
			mergedList = append(mergedList, c2[j])
		}
	}

	return mergedList
}

func (cl ClientDataList) clientMergeSort(cmp_key []byte) {
	if len(cl) <= 1 {
		return
	}

	mid := len(cl) / 2

	left := cl[:mid]
	right := cl[mid:]

	left.ClientMergeSort(cmp_key)
	right.ClientMergeSort(cmp_key)

	mergedList := Merge(left, right)
	copy(cl, mergedList)
}

func (cl ClientDataList) clientListSort(cmpPublicKey []byte) {
	if len(cl) < 100 {
		cl.clientListInsertSort(cmpPublicKey)
	} else {
		cl.clientMergeSort(cmp_key)
	}
}

//function for determening if a public_key is in the client list
func (cl ClientDataList) isPublicKeyInClientList(publicKey []byte, ipPort *net.UDPAddr) bool {
	for i, _ := range cl {
		if (len(ipPort.IP) == net.IPv4len && !isTimeout(cl[i].assoc4.timestamp, BadNodeTimeout)) ||
			(len(ipPort.IP) == net.IPv6len && !isTimeout(cl[i].assoc6.timestamp, BadNodeTimeout)) {
			if publicKeyCmp(cl[i].public_key, publicKey) {
				return true
			}
		}
	}

	return false
}
