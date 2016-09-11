package core

import "net"

const (
	PingNumMax    = 512
	MaxToPing     = 32
	TimeToPing    = 2
	PingPlainSize = 9
	DhtPingSize   = 80
	PingDataSize  = 54

	PublickKeyBytesSize = 32
)

type Ping struct {
	dht        *DHT
	pingArray  PingArray
	toPing     []NodeFormat
	lastToPing uint64
}

func (ping *Ping) sendPingRequest(ipPort *net.UDPAddr, publickKey []byte) error {
	if idEqual(publickKey, ping.dht.selfPublickKey) {
		return &DHTError{"Send ping request: Can't send a ping request to self!"}
	}

	sharedKey := ping.dht.getSharedKey(publickKey)
	data := make([]byte, PingDataSize)

	copy(data[:PublickKeyBytesSize], publickKey)
	//todo
}
