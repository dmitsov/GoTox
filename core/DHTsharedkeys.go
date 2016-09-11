package core

import (
	"github.com/GoKillers/libsodium-go/cryptobox"
	"time"
)

/* Getting a shared key from a SharedKeys containers and if there is no such key
 * for secretKey,publicKey pair generate one. Probably should try to write some DRY code here
 */
func (s SharedKeys) GetSharedKey(publicKey []byte, secretKey []byte) ([]byte, error) {
	var num uint32 = (1 << 32) - 1
	var curr int
	var sharedKey []byte
	for i := 0; i < MaxKeysPerSlot; i++ {
		index := int(publicKey[30])*MaxKeysPerSlot + i
		if s[index].stored {
			if publicKeyCmp(publicKey, s[index].publicKey) {
				sharedKey = make([]byte, cryptobox.CryptoBoxBeforeNmBytes())
				copy(sharedKey, s[index].sharedKey)
				s[index].timesRequested++
				s[index].timeLastRequested = time.Now()
				return sharedKey, nil
			}

			if num != 0 {
				if isTimeout(&(*s)[index].timeLastRequested, KeysTimeout) {
					num = 0
					curr = index
				} else {
					num = s[index].timesRequested
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

	if secretKey == nil {
		return nil, &DHTError{"GetSharedKey: can not create new sharedKey"}
	}
	sharedKey, err := encrypt_precompute(publicKey, secretKey)

	if err != nil {
		return nil, err
	}

	if num != uint32((1<<32)-1) {
		s[curr].stored = true
		s[curr].timesRequested = 1
		s[curr].publicKey = make([]byte, cryptobox.CryptoBoxPublicKeyBytes())
		s[curr].sharedKey = make([]byte, cryptobox.CryptoBoxBeforeNmBytes())
		copy(s[curr].publicKey, publicKey)
		copy(s[curr].sharedKey, sharedKey)
		s[curr].timeLastRequested = time.Now()
	}

	return shared_key, nil
}
