/* This file contains all the needed data structures for the DHT implementation
*  of the go version of the Tox protocol.
 */
package core

import (
	"net"
	"time"
)

//DHT constants
//Maximum number of clients stored per friend

const EnableAssocDHT bool = false

const (
	MaxFriendClients = 8
	LClientNodes     = MaxFriendClients
	LClientLength    = 128
	LClientList      = LClientLength * LClientNodes // a list of clients mathematically closer to you

	MaxCloseToBootstrapNodes = 8
	MaxSentNodes             = 4 //max number of nodes to send with send nodes
	PingTimout               = 5 //ping timeout in seconds
	DHTPingArraySize         = 512

	PingInterval           = 60 //ping interval in seconds for each node in the ping list
	PingsMissedNodeGoesBad = 1  //the number of seconds for a non responsive node to become bad
	PingRoundtrip          = 2
	BadNodeTimeout         = PingInterval + PingsMissedNodeGoesBad*(PingInterval+PingRoundtrip)

	//network variables for transfer over the network
	TOX_AF_INET   = 2
	TOX_AF_INET6  = 10
	TOX_TCP_INET  = 130
	TOX_TCP_INET6 = 138

	DHTFakeFriendNumber = 2 //optimization purposes and onion jittering
	DHTFriendMaxLocks   = 32

	KillNodeTimeout        = BadNodeTimeout + PingInterval
	GetNodeInterval        = 20
	MaxPunchingPorts       = 48
	PunchInterval          = 3
	MaxNormalPunchingTries = 5
	NatPingRequest         = 0
	NatPingResponse        = 1
	MaxBootstrapTimes      = 5

	PackedNodeSizeIP4 = 39
	PackedNodeSizeIP6 = 51

	HardeningAllOk        = 7
	MaxNumberOfSharedKeys = 256 * MaxKeysPerSlot

	NodeFormatSize = 163
)

type AddrTime struct {
	addr      *net.UDPAddr
	timestamp time.Time
}

//error type for DHT operations
type DHTError struct {
	errorMsg string
}

func (e *DHTError) Error() string {
	return e.errorMsg
}

//Structure used for hardening packets in the DHT network
type Hardening struct {
	routesRequestOk        bool      //nodes routes request correctly
	routesRequestTimestamp time.Time // last time this was checked
	routesRequestPingedid  []byte

	sendNodesOk        bool      //node sends correct send node
	sendNodesTimestamp time.Time // last time this was checked
	sendNodesPingedid  []byte

	testingRequest   bool      //node can be used to test other nodes
	testingTimestamp time.Time // last time this was checked
	testingPingId    []byte
}

type IPPTsPng struct {
	ipPort     *net.UDPAddr
	timestamp  time.Time
	lastPinged time.Time

	hardening    Hardening
	retIPPort    *net.UDPAddr
	retTimestamp time.Time
}

type ClientData struct {
	publicKey []byte
	assoc4    IPPTsPng
	assoc6    IPPTsPng
}

type NAT struct {
	holePunching   bool //true if currently holepunching
	punchingIndex  uint32
	tries          uint32
	punchingIndex2 uint32

	punchingTimestamp    time.Time
	recvNATpingTimestamp time.Time
	NATpingId            uint64
	NATpingTimestamp     time.Time
}

type NodeFormat struct {
	publicKey []byte
	ipPort    *net.UDPAddr
}

type DHTFriendCallback struct {
	ipCallback func(interface{}, int32, *net.UDPAddr)
	data       interface{}
	number     int32
}

type DHTFriend struct {
	publicKey  []byte
	clientList ClientDataList

	lastGetNode   time.Time //time at which last get_nodes request was sent
	bootsrapTimes uint32    //number of times get_node packets were sent

	nat NAT

	callbacks []DHTFriendCallback

	toBootstrap    []NodeFormat
	numToBootstrap uint
}

const (
	MaxKeysPerSlot = 4
	KeysTimeout    = 600
)

type SharedKey struct {
	publicKey         []byte
	sharedKey         []byte
	timesRequested    uint32
	stored            bool //field telling us if it's stored or not
	timeLastRequested time.Time
}

type SharedKeys []SharedKey

type CryptoPacketHandlerCallback func(*net.UDPAddr, []byte, []byte) error

type CryptoPacketHandler struct {
	callback CryptoPacketHandlerCallback
	object   interface{}
}

type DHT struct {
	net                 *Networking_Core
	closeClientList     []ClientData
	closeLastGetNodes   time.Time //time of last getnodes request
	closeBootstrapTimes uint32

	secretSymmetricKey []byte

	//DHT keypair
	selfPubclicKey []byte
	selfSecretKey  []byte

	friendList      []DHTFriend
	loadedNodesList []NodeFormat

	sharedKeysRecv SharedKeys
	sharedKeysSent SharedKeys

	ping *Ping

	dhtPingArray       PingArray
	dhtHardenPingArray PingArray

	assoc *Assoc

	lastRunTime time.Time

	cryptoHandlers []CryptoPacketHandler

	toBootstrap NodeList
}

type ClientDataList []ClientData

type NodeList []NodeFormat
