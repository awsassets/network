package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/disembark/network/src/utils"
)

type AesStore struct {
	mp *sync.Map
}

func New() *AesStore {
	return &AesStore{
		mp: &sync.Map{},
	}
}

func (a *AesStore) New(name string) *AesKey {
	key := &AesKey{
		key: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}
	a.mp.Store(name, key)
	return key
}

func (a *AesStore) Get(name string) *AesKey {
	if v, ok := a.mp.Load(name); ok {
		return v.(*AesKey)
	}

	return nil
}

func (a *AesStore) GetOrNew(name string) (*AesKey, bool) {
	key := &AesKey{
		key: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}

	if v, ok := a.mp.LoadOrStore(name, key); ok {
		return v.(*AesKey), false
	}

	return key, true
}

func (a *AesStore) Store(name string, key []byte) {
	a.mp.Store(name, &AesKey{
		key: key,
	})
}

type AesKey struct {
	key []byte
}

func (a *AesKey) Key() string {
	return hex.EncodeToString(a.key)
}

func (a *AesKey) KeyRaw() []byte {
	return a.key
}

func (a *AesKey) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func (a *AesKey) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)
	return data, nil
}
