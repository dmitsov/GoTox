package core

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"math"
	"math/big"
)

//constants defining the different packet types and sizes
const (
	MAX_CRYPTO_REQUEST_SIZE = 1024

	CRYPTO_PACKET_FRIEND_REQ = 32 /* Friend request crypto packet ID. */
	CRYPTO_PACKET_HARDENING  = 48 /* Hardening crypto packet ID. */
	CRYPTO_PACKET_DHTPK      = 156
	CRYPTO_PACKET_NAT_PING   = 254
)

//just translated it from the tox library
func crypto_box_KEYBYTES() int {
	return cryptobox.CryptoBoxBeforeNmBytes()
}

//error type for crypto operations
type CryptoError struct {
	errorMsg string
}

func (e *CryptoError) Error() string {
	return e.errorMsg
}

//used in libsodium to verify if two 32byte keys are equal
func crypto_verify_32(x, y []byte) int {
	var d uint16
	for i := 0; i < 32; i++ {

		d |= uint16(x[i] ^ y[i])
		fmt.Println(d)
	}

	var result int = int(1&(uint16(d-1)>>8)) - 1
	return result
}

//used in libsodium to verify if two 16byte keys are equal
func crypto_verify_16(x, y []byte) int {
	var d uint16
	for i := 0; i < 16; i++ {
		d |= uint16(x[i] ^ y[i])
	}

	var result int = int(1&((d-1)>>8)) - 1
	return result
}

//wrapper for crypto_verify_32
func publicKeyCmp(k1, k2 []byte) bool {
	return crypto_verify_32(k1, k2) == 0
}

//checks if a
func public_key_valid(publick_key []byte) bool {
	return publick_key[31] < 128
}

func random_int() uint32 {
	r, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	if err != nil {
		return 0
	}
	return uint32(r.Uint64())
}

func random_64() uint64 {
	var max *big.Int = big.NewInt(math.MaxUint32)
	max = max.Add(max, big.NewInt(math.MaxUint32))
	max = max.Add(max, big.NewInt(1))

	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0
	}
	return r.Uint64()
}

func encrypt_precompute(public_key, secret_key []byte) ([]byte, error) {
	data, errCode := cryptobox.CryptoBoxBeforeNm(public_key, secret_key)
	if errCode != 0 {
		return nil, &CryptoError{"Unable to precompute the new key"}
	}

	return data, nil
}

func encrypt_data_symmetric(secret_key []byte, nonce []byte, plainData []byte) ([]byte, error) {
	if len(plainData) == 0 {
		return nil, &CryptoError{"No data to encrypt!"}
	}

	if len(secret_key) == 0 || len(nonce) == 0 {
		return nil, &CryptoError{"No secret key or nonce added!"}
	}

	tempData := make([]byte, cryptobox.CryptoBoxZeroBytes())
	tempData = append(tempData, plainData...)
	encryptedData, errorCode := cryptobox.CryptoBoxAfterNm(tempData, nonce, secret_key)
	if errorCode != 0 {
		return nil, &CryptoError{"Failed symmetric encryption"}
	}

	return encryptedData[cryptobox.CryptoBoxBoxZeroBytes():], nil
}

func decrypt_data_symmetric(secret_key, nonce []byte, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) <= cryptobox.CryptoBoxBoxZeroBytes() {
		return nil, &CryptoError{"Wrong encrypted data length!"}
	}

	if len(secret_key) == 0 || len(nonce) == 0 {
		return nil, &CryptoError{"No secret key or nonce added!"}
	}

	tempData := make([]byte, cryptobox.CryptoBoxBoxZeroBytes())
	tempData = append(tempData, encryptedData...)
	decryptedData, errorCode := cryptobox.CryptoBoxOpenAfterNm(tempData, nonce, secret_key)
	if errorCode != 0 {
		return nil, &CryptoError{"Failed symmetric decryption"}
	}

	return decryptedData[cryptobox.CryptoBoxZeroBytes():], nil
}

func encrypt_data(public_key, secret_key []byte, nonce []byte, plainData []byte) ([]byte, error) {
	if len(public_key) == 0 || len(secret_key) == 0 {
		return nil, &CryptoError{"Empty secret key or publick key"}
	}

	k, err := encrypt_precompute(public_key, secret_key)
	if err != nil {
		return nil, err
	}

	encryptedData, err := encrypt_data_symmetric(k, nonce, plainData)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}

func decrypt_data(public_key, secret_key []byte, nonce []byte, encryptedData []byte) ([]byte, error) {
	if len(public_key) == 0 || len(secret_key) == 0 {
		return nil, &CryptoError{"Empty secret key or publick key"}
	}

	k, err := encrypt_precompute(public_key, secret_key)

	if err != nil {
		return nil, err
	}

	plainData, err := decrypt_data_symmetric(k, nonce, encryptedData)
	if err != nil {
		return nil, err
	}

	return plainData, nil
}

//increment nonce by one
func increment_nonce(nonce []byte) {
	var carry uint16 = 1
	for i := cryptobox.CryptoBoxNonceBytes(); i > 0; i-- {
		carry += uint16(nonce[i])
		nonce[i] = byte(carry)
		carry = uint16(byte(carry) >> 8)
	}
}

//increment nonce by a number
func increment_nonce_by_number(nonce []byte, host_order_num uint32) {
	bigEndianNum := make([]byte, 4)
	binary.BigEndian.PutUint32(bigEndianNum, host_order_num)
	var num_as_nonce []byte = make([]byte, cryptobox.CryptoBoxNonceBytes())
	num_as_nonce[cryptobox.CryptoBoxNonceBytes()-4] = bigEndianNum[0]
	num_as_nonce[cryptobox.CryptoBoxNonceBytes()-3] = bigEndianNum[1]
	num_as_nonce[cryptobox.CryptoBoxNonceBytes()-2] = bigEndianNum[2]
	num_as_nonce[cryptobox.CryptoBoxNonceBytes()-1] = bigEndianNum[3]

	var carry uint16
	for i := cryptobox.CryptoBoxNonceBytes() - 1; i >= 0; i-- {
		carry += uint16(nonce[i]) + uint16(num_as_nonce[i])
		nonce[i] = byte(carry)
		carry = uint16(byte(carry) >> 8)
	}
}

func randombytes(data []byte) {
	for i, _ := range data {
		r, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint8))
		data[i] = byte(r.Uint64())
	}
}

func random_nonce() []byte {
	nonce := make([]byte, cryptobox.CryptoBoxNonceBytes())
	randombytes(nonce)
	return nonce
}

func new_symmetric_key() []byte {
	key := make([]byte, crypto_box_KEYBYTES())
	randombytes(key)
	return key
}

func new_nonce() []byte {
	return random_nonce()
}

//Create request to peer
func create_request(send_public_key, send_secret_key []byte, recv_public_key []byte, data []byte, request_id byte) ([]byte, error) {
	if len(send_public_key) == 0 || len(send_secret_key) == 0 ||
		len(recv_public_key) == 0 {
		return nil, &CryptoError{"A key hasn't been passed"}
	}

	if len(data) == 0 {
		return nil, &CryptoError{"No data to send"}
	}

	if MAX_CRYPTO_REQUEST_SIZE < len(data)+1+cryptobox.CryptoBoxPublicKeyBytes()*2+cryptobox.CryptoBoxNonceBytes()+1+cryptobox.CryptoBoxMacBytes() {
		return nil, &CryptoError{"Send data too large"}
	}

	packet := make([]byte, 1)
	nonce := make([]byte, cryptobox.CryptoBoxNonceBytes())

	copy(nonce, new_nonce())
	dataToEncrypt := make([]byte, 1)
	dataToEncrypt[0] = request_id
	dataToEncrypt = append(dataToEncrypt, data...)

	encryptedData, err := encrypt_data(recv_public_key, send_secret_key, nonce, dataToEncrypt)

	if err != nil {
		return nil, err
	}

	packet[0] = NetPacketCrypto
	packet = append(packet, recv_public_key...)
	packet = append(packet, send_public_key...)
	packet = append(packet, nonce...)
	packet = append(packet, encryptedData...)

	return packet, nil
}

//function to handle a received crypto request
func handle_request(send_public_key, send_secret_key []byte, recv_public_key []byte, packet []byte, request_id *byte) ([]byte, error) {
	if len(send_public_key) == 0 || len(send_secret_key) == 0 ||
		len(recv_public_key) == 0 {
		return nil, &CryptoError{"A key hasn't been passed"}
	}

	if len(packet) == 0 {
		return nil, &CryptoError{"No data to decrypt"}
	}

	if (len(packet) < cryptobox.CryptoBoxPublicKeyBytes()*2+cryptobox.CryptoBoxNonceBytes()+1+cryptobox.CryptoBoxMacBytes()) ||
		len(packet) > MAX_CRYPTO_REQUEST_SIZE {
		return nil, &CryptoError{"Wrong encrypted data format!"}
	}

	if !public_key_cmp(packet[1:cryptobox.CryptoBoxPublicKeyBytes()+1], send_public_key) {
		return nil, &CryptoError{"Mismatched public keys!"}
	}

	copy(recv_public_key, packet[1+cryptobox.CryptoBoxPublicKeyBytes():1+cryptobox.CryptoBoxPublicKeyBytes()*2])

	nonce := packet[1+cryptobox.CryptoBoxPublicKeyBytes()*2 : 1+cryptobox.CryptoBoxPublicKeyBytes()*2+cryptobox.CryptoBoxNonceBytes()]

	decryptedData, err := decrypt_data(recv_public_key, send_secret_key, nonce, packet[cryptobox.CryptoBoxPublicKeyBytes()*2+cryptobox.CryptoBoxNonceBytes()+1:])

	if err != nil {
		return nil, err
	}

	if len(decryptedData) == 0 {
		return nil, &CryptoError{"No data to decrypt"}
	}

	*request_id = decryptedData[0]
	return decryptedData[1:], nil
}
