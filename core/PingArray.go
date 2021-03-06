package core

import (
	"fmt"
	"time"
)

type PingArrayError struct {
	errorMsg string
}

func (e *PingArrayError) Error() string {
	return e.errorMsg
}

type PingArrayEntry struct {
	data     []byte    // data
	pingTime time.Time //time of creation
	ping_id  uint64    // ping id
}

type PingArray struct {
	entries      []PingArrayEntry
	last_added   uint32 //index for the last added entry
	last_deleted uint32 //index for deleting the next entry
	timeout      uint32 //timeout in microseconds after which the ping entries must be cleared
}

func isTimeout(t *time.Time, timeout uint64) bool {
	return t.UnixNano()/int64(time.Microsecond)+int64(timeout) >= int64(time.Now().UnixNano()/int64(time.Microsecond))
}

func (a *PingArray) isTimedout(e *PingArrayEntry) bool {
	return e.pingTime.UnixNano()/int64(time.Microsecond)+int64(a.timeout) >= int64(time.Now().UnixNano()/int64(time.Microsecond))
}

func (a *PingArray) ClearTimeout() {
	for ; a.last_deleted != a.last_added; a.last_deleted++ {
		a.last_deleted = a.last_deleted % uint32(len(a.entries))
		if !a.isTimedout(&a.entries[a.last_deleted]) {
			return
		}

		a.entries[a.last_deleted].data = nil
		a.entries[a.last_deleted].ping_id = 0
	}
}

func (a *PingArray) Add(data []byte) uint64 {
	a.ClearTimeout()
	a.entries[a.last_added].data = make([]byte, len(data))
	copy(a.entries[a.last_added].data, data)
	a.entries[a.last_added].pingTime = time.Now()
	ping_id := random_64()
	ping_id /= uint64(len(a.entries))
	ping_id *= uint64(len(a.entries))
	ping_id += uint64(a.last_added)

	if ping_id == 0 {
		ping_id += uint64(len(a.entries))
	}

	a.entries[a.last_added].pingTime = time.Now()
	a.entries[a.last_added].ping_id = ping_id
	a.last_added++
	a.last_added = a.last_added % uint32(len(a.entries))

	return ping_id
}

func (a *PingArray) Check(data []byte, ping_id uint64) (int, error) {
	if ping_id == 0 {
		return 0, &PingArrayError{"Invalied ping_id"}
	}

	index := ping_id % uint64(len(a.entries))

	if ping_id != a.entries[index].ping_id {
		return 0, &PingArrayError{fmt.Sprintf("There is no ping_id %d", ping_id)}
	}

	if a.isTimedout(&a.entries[index]) {
		return 0, &PingArrayError{fmt.Sprintf("Ping_id %d has timedout", ping_id)}
	}

	if len(a.entries[index].data) == 0 {
		return 0, &PingArrayError{"No data in ping entry"}
	}

	if len(a.entries[index].data) > len(data) {
		return 0, &PingArrayError{"Not enough memory space"}
	}

	n := len(data)
	if n > len(a.entries[index].data) {
		n = len(a.entries[index].data)
	}

	copy(data, a.entries[index].data)
	a.entries[index].data = nil
	a.entries[index].pingTime = time.Now()

	return n, nil
}

func (a *PingArray) Clear() {
	for i, _ := range a.entries {
		a.entries[i].data = nil
		a.entries[i].ping_id = 0
		a.entries[i].pingTime = time.Time{}
	}

	a.last_added = 0
	a.last_deleted = 0
}

func NewPingArray(size, timeout uint32) (*PingArray, error) {
	if size == 0 || timeout == 0 {
		return nil, &PingArrayError{"Wrong input"}
	}

	array := new(PingArray)
	array.entries = make([]PingArrayEntry, size)
	array.timeout = timeout

	return array, nil
}
