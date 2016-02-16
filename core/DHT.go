package core

import(
	"time"	
)

type PingArrayEntry struct{
	data []byte
	pingTime time.Time
	ping_id uint64
}


type PingArray struct {
	entries []PingArrayEntries
	
	last_added uint32 //index for the last added entry
	last_deleted uint32 //index for deleting the next entry	
	timeout uint32 //timout after which the ping entries must be cleared
}


func (a *PingArray) Add(data []byte){
	
}


