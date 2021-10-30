package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/disembark/network/src/utils"
)

const BlockSize = aes.BlockSize

type AesStore struct {
	mp *sync.Map
}

func New() *AesStore {
	a := &AesStore{
		mp: &sync.Map{},
	}

	go a.runner()

	return a
}

func (a *AesStore) runner() {
	tick := time.NewTicker(time.Minute * 5)
	for range tick.C {
		a.clean()
	}
}

func (a *AesStore) clean() {
	a.mp.Range(func(key, value interface{}) bool {
		if value.(*AesKey).lastUsed.Before(time.Now().Add(-time.Minute * 30)) {
			a.mp.Delete(key)
		}
		return true
	})
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
	key      []byte
	lastUsed time.Time
}

func (a *AesKey) Key() string {
	return hex.EncodeToString(a.key)
}

func (a *AesKey) KeyRaw() []byte {
	return a.key
}

func (a *AesKey) Revive() {
	a.lastUsed = time.Now()
}

func (a *AesKey) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(data[aes.BlockSize:], data[aes.BlockSize:])
	return data, nil
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
