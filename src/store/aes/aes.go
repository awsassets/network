package aes_store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/disembark/network/src/utils"
)

const BlockSize = aes.BlockSize

type Store struct {
	mp     *cache.Cache
	ctx    context.Context
	cancel context.CancelFunc
}

func New() *Store {
	ctx, cancel := context.WithCancel(context.Background())
	a := &Store{
		mp:     cache.New(time.Minute*5, time.Minute*30),
		ctx:    ctx,
		cancel: cancel,
	}

	return a
}

func (a *Store) New(name string) *Key {
	key := &Key{
		key: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}
	a.mp.Store(name, key)
	return key
}

func (a *Store) Get(name string) *Key {
	if v, ok := a.mp.Get(name); ok {
		return v.(*Key)
	}

	return nil
}

func (a *Store) GetOrNew(name string) (*Key, bool) {
	key := &Key{
		key: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}

	if v, ok := a.mp.StoreOrGet(name, key); ok {
		return v.(*Key), false
	}

	return key, true
}

func (a *Store) Store(name string, key []byte) {
	a.mp.Store(name, &Key{
		key: key,
	})
}

func (a *Store) Revive(name string) {
	a.mp.Expire(name, time.Now().Add(time.Minute*30))
}

type Key struct {
	key []byte
}

func (a *Key) Key() string {
	return hex.EncodeToString(a.key)
}

func (a *Key) KeyRaw() []byte {
	return a.key
}

func (a *Key) Encrypt(data []byte) ([]byte, error) {
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

func (a *Key) Decrypt(data []byte) ([]byte, error) {
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
