package aes_store

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/disembark/network/src/packet"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_Aes(t *testing.T) {
	aes := New()
	defer aes.Stop()

	hash := func(data []byte) string {
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	}

	key := "test"

	aesKey := aes.New(key)

	assert.Equal(t, aesKey, aes.Get(key), "Keys are stored")
	k, ok := aes.GetOrNew(key)
	assert.Equal(t, false, ok, "New key is not created")
	assert.Equal(t, aesKey, k, "Keys are stored")

	key = "test2"
	k, ok = aes.GetOrNew(key)
	assert.Equal(t, true, ok, "New key is created")
	assert.NotEqual(t, aesKey, k, "Key is not the old key")

	aes.Store(key, aesKey.KeyRaw())
	aes.Revive(key)

	pkt := make([]byte, packet.MTU+BlockSize)
	_, _ = rand.Read(pkt[BlockSize:])

	clone := make([]byte, len(pkt))
	copy(clone, pkt)

	encrypted, err := aesKey.Encrypt(pkt)
	assert.ErrorIs(t, err, nil, "no error on encryption")

	assert.NotEqual(t, hash(encrypted[BlockSize:]), hash(clone[BlockSize:]), "Encrypted data should not be plaintext")

	decrypted, err := aesKey.Decrypt(encrypted)
	assert.ErrorIs(t, err, nil, "no error on decryption")
	assert.Equal(t, hash(decrypted), hash(clone[BlockSize:]), "Decrypted data should be the same")

	assert.Equal(t, hex.EncodeToString(aesKey.KeyRaw()), aesKey.Key(), "Key is hex")
}
