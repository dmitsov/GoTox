package core

import (
	"net"
	"time"
	"sort"
	"syscall"
)

const (
	Bad = iota
	SeenbHeardg
	Seeng
	Used
)

const (
	DistanceIndexDistanceBits = 44
	AssocBucketRefres         = 45 // time interval in seconds for refreshing the buckets
	HashCollideCount          = 5

	HashCollidePrime = 101

	CandidatesSeenTimeout  = 1800
	CandidatesHeardTimeout = 600

	DistanceIndexIndexBits = (64 - DistanceIndexDistanceBits)
	DistanceIndexIndexMask = ((1 << DistanceIndexIndexBits) - 1)
)

const (
	ProtoIPv4 = iota
		ProtoIPv6
		LANok
)

type hash uint32
type bucket uint16
type usecnt uint16

type assocDistanceRelativeCallback func(data interface{}, clientId, clientId1, clientId2 []byte) int
type assocDistanceAbsoluteCallback func(data interface{}, clientIdRef, clientIdCheck []byte) uint64

type CandidatesBucket []ClientEntry

type Assoc struct {
	selfHash     hash
	selfClientId []byte

	candidatesBucketBits  uint32
	candidatesBucketSize  uint32
	candidatesBucketCount uint32

	getNodes time.Time

	candidates []CandidatesBucket
}

type ClientEntry struct {
	hash     hash
	getnodes time.Time
	used_at  time.Time
	seen_at  time.Time
	heardAt time.Time

	seen_family  byte
	heard_family byte

	assocHeard4 net.UDPAddr
	assocHeard6 net.UDPAddr

	clientData ClientData
}

type AssocCloseEntries struct {
	customData interface{}
	wantedId   []byte
	flags      byte

	customRelativeFunc assocDistanceRelativeCallback
	customAbsoluteFunc assocDistanceAbsoluteCallback

	countGood byte
	count     byte
	result    []ClientDataList
}

func NewAssocDefault(publicId []byte) (*Assoc, error) {

}

func NewAssoc(bits, entries uint, publicId []byte) (*Assoc, error)

func (dht *DHT) doAssoc(assoc *Assoc)

func (assoc *Assoc) killAssoc()

func (assoc *Assoc) addEntry(id []byte, ipptsSend IPPTsPng, ipPortRecv *net.UDPAddr, used byte)

func (assoc *Assoc) getCloseEntries() ([]AssocCloseEntries, error)

func (assoc *Assoc) selfClientIdChanged(publicId []byte)

func (assoc *Assoc) idDistance(data interface{}, idRef, idCheck []byte) (retval uint64) {
	var pos byte
	var bits byte = DistanceIndexDistanceBits

	for bits > 8 {
		distance := ^byte((int8(idRef[pos] ^ idCheck[pos]) - 1))
		retVal = (retVal << 8) | distance
		bits -= 8
		pos++
	}
}

func (assoc *Assoc) distIndexEntry(distIndex uint64) (client *ClientEntry) {
	if distIndex & DistanceIndexIndexMask == DistanceIndexIndexMask {
		return
	}

	total := assoc.candidatesBucketCount * assoc.candidatesBucketSize
	index := distIndex & DistanceIndexIndexMask

	if index < total {
		bucketId := index / assoc.candidatesBucketSize
		bucket := assoc.candidates[bucketId]
		
		clientEntryId := index % assoc.candidatesBucketSize
		entry := bucket[clientEntryId]
		
		if entry.hash > 0 {
			client = entry			
		}
	}
} 

func (assoc *Assoc) distIndexId(distIndex) []byte {
	clientEntry := distIndexEntry(distIndex)
	if clientEntry != nil {
		return clientEntry.client.publicKey
	}	

	return nil
}

func (assoc *Assoc) distIndexSelectionSort(distList []uint64, first, last int, id []byte, customData interface{}, distRelCallback assocDistanceRelativeCallback) {
	for i := first; i < last; i++ {
		id1 := assoc.distIndexId(distList[i])

		for j := i + 1; j <= last; j ++ {
			id2 := assoc.distIndexId(distList[i])
			if id1 != nil && id2 != nil && distRelCallback(customData, id, id1, id2) == 2 {
				temp := distList[i]
				distList[i] = distList[j]
				distList[j] = temp
			}
		}
	}	
}

func (assoc *Assoc) idHash(id []byte) uint32 {
	var res uint32 = 0x19a64e82
	for i := 0; i < 32; i++ {
		res = (res << 1) ^ id[i] + (res >> 31)
	}

	if res % assoc.candidatesBucketSize == 0 {
		res++
	}

	return res
}

func (assoc *Assoc) hashCollide(h hash) hash {
	hash64 := (h * HashCollidePrime) % assoc.candidateBucketSize
	
	if hash64 == 0 {
		hash64 = 1
	}

	return hash64
}

func (client *ClientEntry)	entryAssoc(isIPv4 bool) *IPPTsPng {
	if client == nil {
		return nil
	}	
	
	if isIPv4 {
		return client.assoc4
	} else {
		return client.assoc6
	}
}

func (client *ClientEntry) entryHeardGet(isIPv4 bool) *net.UDPAddr {
	if client == nil {
		return nil
	}

	if isIPv4 {
		return client.assocHeard4
	} else {
		return client.assocHeard6
	}
}


// function for storing heard data 
// returns true when successfull
func (client *ClientEntry) entryHeardStore(ippts *IPPTsPng) bool {
	if client == nil || ippts == nil || !ipPortIsSet(ippts.ipPort) {
		return false
	}

	ipPort := ippts.ipPort
	var heard *net.UDPAddr

	if len(ipPort.IP) != net.IPv4zero || len(ipPort.IP) != net.IPv6zero {
		return false
	}

	if ipPort.IP.To4() != nil {
		heard = client.assocHeard4		
	} else {
		heard = client.assocHeard6
	}

	if ipPortEqual(ipPort, heard) || (!isLAN(ipPort.IP) && !isLAN(heard.IP) && !isTimeout(entry.heardAt, CandidatesHeardTimeout)) {
		return false
	}
	
	*heard = *ipPort
	client.heardAt = ippts.timestamp
	if ipPort.IP.To4() != nil {
		client.heardFamily = syscall.AF_INET
	} else {
		client.heardFamily = syscall.AF_INET6
	}
	return true
}

func (assoc *Assoc) idClosest(callbackData interface{}, clientId, id1, id2 []byte) int {
	return idCloses(id, id1, id2)
}

func idBucket(id []byte, bits byte) bucket {
	var retval bucket
	pos := 0

	for bits > 8 {
		retval = (retval << 8) | id[pos++]
		bits -= 8
	}

	return (retval << 8) | (id[pos] >> (8 - bits))
}

//************************************************************************************
// 								CANDIDATES FUNCTIONS
//************************************************************************************

func (assoc *Assoc) candidateBucketId(id []byte) bucket {
	return idBucket(id, assoc.candidateBucketBits)
}

// function for searching candidates
func (assoc *Assoc) searchCandidates(id []byte, h hash) (client *ClientEntry, bool) {
		
}
