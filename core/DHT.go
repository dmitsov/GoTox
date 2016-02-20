package core

import (
	"encoding/binary"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"net"
	"time"
)

type Ping struct {
}

//DHT constants
//Maximum number of clients stored per friend
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
	routes_request_ok        bool      //nodes routes request correctly
	routes_request_timestamp time.Time // last time this was checked
	routes_request_pingedid  []byte

	send_nodes_ok        bool      //node sends correct send node
	send_nodes_timestamp time.Time // last time this was checked
	send_nodes_pingedid  []byte

	testing_requests  bool      //node can be used to test other nodes
	testing_timestamp time.Time // last time this was checked
	testing_ping_id   []byte
}

type IPPTsPng struct {
	ip_port     *net.UDPAddr
	timestamp   time.Time
	last_pinged time.Time

	hardening     Hardening
	ret_ip_port   *net.UDPAddr
	ret_timestamp time.Time
}

type ClientData struct {
	public_key []byte
	assoc4     IPPTsPng
	assoc6     IPPTsPng
}

type NAT struct {
	hole_punching   bool //true if currently holepunching
	punching_index  uint32
	tries           uint32
	punching_index2 uint32

	punching_timestamp    time.Time
	recvNATping_timestamp time.Time
	NATping_id            uint64
	NATping_timestamp     time.Time
}

type NodeFormat struct {
	public_key []byte
	ip_port    *net.UDPAddr
}

type DHTFriendCallback struct {
	ip_callback func(interface{}, int32, *net.UDPAddr)
	data        interface{}
	number      int32
}

type DHTFriend struct {
	public_key  []byte
	client_list [MaxFriendClients]ClientData

	lastGetNode    time.Time //time at which last get_nodes request was sent
	bootsrap_times uint32    //number of times get_node packets were sent

	nat NAT

	callbacks [DHTFriendMaxLocks]DHTFriendCallback

	to_bootstrap     [MaxSentNodes]NodeFormat
	num_to_bootstrap uint
}

const (
	MaxKeysPerSlot = 4
	KeysTimeout    = 600
)

type SharedKey struct {
	public_key        []byte
	shared_key        []byte
	times_requested   uint32
	stored            bool //field telling us if it's stored or not
	timeLastRequested time.Time
}

type Shared_Keys [256 * MaxKeysPerSlot]SharedKey

type CryptoPacketHandlerCallback func(interface{}, *net.UDPAddr, []byte, []byte) error

type CryptoPacketHandler struct {
	callback CryptoPacketHandlerCallback
	object   interface{}
}

type DHT struct {
	net                   *Networking_Core
	close_clientlist      [LClientList]ClientData
	close_lastgetnodes    time.Time //time of last getnodes request
	close_bootstrap_times uint32

	secret_symmetric_key []byte

	//DHT keypair
	self_pubclic_key []byte
	self_secret_key  []byte

	friendList      []DHTFriend
	loadedNodesList []NodeFormat

	shared_keys_recv Shared_Keys
	shared_keys_sent Shared_Keys

	ping *Ping

	dht_ping_array        PingArray
	dht_harden_ping_array PingArray

	assoc *Assoc

	last_run_time time.Time

	cryptopackethandlers [256]CryptoPacketHandler

	to_bootstrap     [MaxCloseToBootstrapNodes]NodeFormat
	num_to_bootstrap uint
}

func id_closest(cmp_pk, pk1, pk2 []byte) []byte {
	for i := 0; i < cryptobox.CryptoBoxPublicKeyBytes(); i++ {
		d1 := cmp_pk[i] ^ pk1[i]
		d2 := cmp_pk[i] ^ pk2[i]

		if d1 < d2 {
			return pk1
		} else if d1 > d2 {
			return pk2
		}
	}

	return nil
}

func bit_by_bit_cmp(pk1, pk2 []byte) int {
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

/* Getting a shared key from a shared_keys containers and if there is no such key
 * for secret_key,public_key pair generate one
 */
func (s *Shared_Keys) get_shared_key(secret_key, public_key []byte) ([]byte, error) {
	var num uint32 = (1 << 32) - 1
	var curr int

	for i := 0; i < MaxKeysPerSlot; i++ {
		index := int(public_key[30])*MaxKeysPerSlot + i
		if (*s)[index].stored {
			if public_key_cmp(public_key, (*s)[index].public_key) {
				shared_key := make([]byte, cryptobox.CryptoBoxBeforeNmBytes())
				copy(shared_key, (*s)[index].shared_key)
				(*s)[index].times_requested++
				(*s)[index].timeLastRequested = time.Now()
				return shared_key, nil
			}

			if num != 0 {
				if isTimeout(&(*s)[index].timeLastRequested, KeysTimeout) {
					num = 0
					curr = index
				} else {
					num = (*s)[index].times_requested
					curr = index
				}
			}
		} else {
			if num != 0 {
				num = 0
				curr = index
			}
		}
	}

	shared_key, err := encrypt_precompute(public_key, secret_key)

	if err != nil {
		return nil, err
	}

	if num != uint32((1<<32)-1) {
		(*s)[curr].stored = true
		(*s)[curr].times_requested = 1
		(*s)[curr].public_key = make([]byte, cryptobox.CryptoBoxPublicKeyBytes())
		(*s)[curr].shared_key = make([]byte, cryptobox.CryptoBoxBeforeNmBytes())
		copy((*s)[curr].public_key, public_key)
		copy((*s)[curr].shared_key, shared_key)
		(*s)[curr].timeLastRequested = time.Now()
	}

	return shared_key, nil
}

//Get shared key to encrypt/decrypt DHT packet from public_key into shared_key
//For packets that we receive
func (d *DHT) DHTGetSharedKeyRecv(public_key []byte) ([]byte, error) {
	return d.shared_keys_recv.get_shared_key(d.self_secret_key, public_key)
}

//Get shared key to encrypt/decrypt DHT packet fromt public_key into shared_key
//for packets that we send
func (d *DHT) DHTGetSharedKeySent(public_key []byte) ([]byte, error) {
	return d.shared_keys_sent.get_shared_key(d.self_secret_key, public_key)
}

func toNetFamily(ip net.IP) (int, error) {
	if len(ip) == net.IPv4len {
		return TOX_AF_INET, nil
	} else if len(ip) == net.IPv6len {
		return TOX_AF_INET6, nil
	}

	return 0, &NetError{"Wrong ip length", ip, 0}
}

func packed_node_size(ip net.IP) (int, error) {
	switch {
	case len(ip) == net.IPv4len:
		return PackedNodeSizeIP4, nil
	case len(ip) == net.IPv6len:
		return PackedNodeSizeIP6, nil
	}

	return 0, &NetError{"Wrong ip length", ip, 0}
}

//function for packing nodes in network format
func pack_nodes(nodes []NodeFormat) ([]byte, error) {
	var data []byte = make([]byte, 0)

	for i, _ := range nodes {
		var net_family byte
		switch {
		case len(nodes[i].ip_port.IP) == 4:
			net_family = TOX_AF_INET
		case len(nodes[i].ip_port.IP) == 16:
			net_family = TOX_AF_INET6
		default:
			return nil, &DHTError{"Wrong ip type in nodes!" + fmt.Sprintf("%v", nodes[i].ip_port.IP)}
		}

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

//function for unpacking nodes
func unpack_nodes(data []byte) ([]NodeFormat, error) {
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

type ClientDataList []ClientData

func ipport_equal(p1,p2 *net.UDPAddr) bool {
	if len(p1.IP) != len(p2.IP) {
		return false
	}	
	
	for i,_ := range p1.IP {
		if p1.IP[i]	!= p2.IP[i] {
			return false
		}
	}

	return p1.Port == p2.Port
}


func (list ClientDataList) ClientOrIPPortInList(public_key []byte,ip_port *net.UDPAddr)(,bool){
	for i,_ := range list {
		if public_key_cmp(list[i].public_key,public_key){
			if len(ip_port.IP) == net.IPv4len {
				list[i].assoc4.ip_port.IP = make([]byte,net.IPv4len)
				copy(list[i].assoc4.ip_port.IP,ip_port.IP)
				list[i].assoc4.ip_port.Port = ip_port.Port
				list[i].assoc4.timestamp = time.Now()
			} else if len(ip_port.IP) == net.IPv6len {
				list[i].assoc6.ip_port.IP = make([]byte,net.IPv6len)
				copy(list[i].assoc6.ip_port.IP,ip_port.IP)
				list[i].assoc6.ip_port.Port = ip_port.Port
				list[i].assoc6.timestamp = time.Now()
			}
			
			return true
		}
	}

	for i,_ := range list {
		if len(ip_port.IP) == net.IPv4len && ipport_equal(list[i].assoc4.ip_port,ip_port){
			list[i].assoc4.timestamp = time.Now()
			copy(public_key,list[i].public_key)
			list[i].assoc6 = IPPTsPng{}
			return true
		} else len(ip_port.IP) == net.IPv6len && ipport_equal(list.assoc6.ip_port,ip_port) {
			list[i].assoc6.timestamp = time.Now()
			copy(public_key,list[i].public_key)
			list[i].assoc4 = IPPTsPng{}
			return true
		}
	}

	return false
}

