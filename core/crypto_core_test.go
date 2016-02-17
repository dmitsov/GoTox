package core

import (
	"fmt"
	"github.com/GoKillers/libsodium-go/sodium"
	"strconv"
	"testing"
)

func TestKeyCmp(t *testing.T) {
	key := new_symmetric_key()
	var keyStr string
	for _, v := range key {
		keyStr += strconv.FormatInt(int64(v), 16)
	}

	fmt.Printf(keyStr)
	if !public_key_cmp(key, key) {
		t.Fatal()
	}
}

func TestEncryptDecrypt(t *testing.T) {
	sodium.Init()
	plainText := "Hello world!"
	public_key := new_symmetric_key()
	//	secret_key := new_symmetric_key()
	secret_key2 := new_symmetric_key()
	nonce := new_nonce()

	encryptedData, err := encrypt_data(public_key, secret_key2, nonce, []byte(plainText))

	if err != nil {
		t.Error(err.Error())
	}

	fmt.Printf("Encrypted:%s\n", encryptedData)

	decryptedData, err := decrypt_data(public_key, secret_key2, nonce, encryptedData)
	if err != nil {
		t.Error(err.Error())
	}

	fmt.Printf("Decrypted: %s\n", decryptedData)
	if string(decryptedData) != plainText {
		t.Fail()
	}
}

/*
func TestCreateHandleRequest(t *testing.T) {
//	t.Skip()
	//sodium.Init()
	plainText := "Hello world!"
	public_key1 := new_symmetric_key()
	secret_key1 := new_symmetric_key()

	public_key2 := new_symmetric_key()
	secret_key2 := new_symmetric_key()

	encryptedData, err := create_request(public_key2, secret_key2, public_key2, []byte(plainText), CRYPTO_PACKET_FRIEND_REQ)

	fmt.Printf("Keybytes: %d\n", cryptobox.CryptoBoxPublicKeyBytes())

	if err != nil {
		t.Error(err.Error())
	}

	fmt.Printf("Encrypted:%s\n", encryptedData)
	test_key := make([]byte,32)
	var request_id byte
	decryptedData, err := handle_request(public_key2, secret_key2, test_key, encryptedData, &request_id)
	if err != nil {

		t.Error(err.Error())
	}

	for k,v := range test_key {
		if v != public_key1[k] {
			fmt.Println("Wrong key")
			break
		}
	}

	fmt.Printf("Decrypted: %s\n", decryptedData)
	if string(decryptedData) != plainText || request_id != CRYPTO_PACKET_FRIEND_REQ {
		t.Fail()
	}
}*/
