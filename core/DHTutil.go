package core

import (
	"github.com/GoKillers/libsodium-go/cryptobox"
	"net"
)

func idClosest(cmpPk, pk1, pk2 []byte) []byte {
	for i := 0; i < cryptobox.CryptoBoxPublicKeyBytes(); i++ {
		d1 := cmpPk[i] ^ pk1[i]
		d2 := cmpPk[i] ^ pk2[i]

		if d1 < d2 {
			return pk1
		} else if d1 > d2 {
			return pk2
		}
	}

	return nil
}

func bitByBitCmp(pk1, pk2 []byte) int {
	for i := 0; i < cryptobox.CryptoBoxPublicKeyBytes(); i++ {
		if pk1[i] == pk2[i] {
			continue
		}

		for j := 0; j < 8; j++ {
			if (pk1[i] & (1 << (7 - byte(j)))) != (pk2[i] & (1 << (7 - byte(j)))) {
				return i*8 + j
			}
		}
	}

	return -1
}

func ipReset(ip net.IP) {
	if len(ip) == net.IPv4len {
		copy(ip, net.IPv4zero)
	} else if len(ip) == net.IPv6len {
		copy(ip, net.IPv6Zero)
	}
}

func toIpv4(ipPort *net.UDPAddr) {
	if len(ipPort.IP) == net.IPv6len {
		ip4 := ipPort.IP.ToIPv4()
		if ip4 != nil {
			ipPort.IP = ip4
		}
	}
}

//TODO: add saFamily parameter better for the tox tcp constants
func toNetFamily(ip net.IP) (int, error) {
	if len(ip) == net.IPv4len {
		return TOX_AF_INET, nil
	} else if len(ip) == net.IPv6len {
		return TOX_AF_INET6, nil
	}

	return 0, &NetError{"Wrong ip length", ip, 0}
}

//helper function for node lookup
func ipPortEqual(p1, p2 *net.UDPAddr) bool {

	return len(p1.IP) == len(p2.IP) && p1.Port == p2.Port && p1.IP.Equal(p2.IP)
}

func min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

//wrapper function for publicKeyCmp
func idEqual(pk1, pk2 []byte) bool {
	return publicKeyCmp(pk1, pk2)
}

//TODO: finish this function
func (ipptrPng *IPPTsPng) Clear() {

}
