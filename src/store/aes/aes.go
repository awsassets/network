package aes_store

import (
	"context"
	"crypto/aes"
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/disembark/network/src/utils"
)

const BlockSize = aes.BlockSize

type AesStore struct {
	mp     cache.Cache
	ctx    context.Context
	cancel context.CancelFunc
}

type MockAesStore struct {
	NewFunc      func(name string) Key
	GetFunc      func(name string) Key
	GetOrNewFunc func(name string) (Key, bool)
	StoreFunc    func(name string, key []byte)
	ReviveFunc   func(name string)
	StopFunc     func()
}

func (a MockAesStore) New(name string) Key {
	return a.NewFunc(name)
}

func (a MockAesStore) Get(name string) Key {
	return a.GetFunc(name)
}

func (a MockAesStore) GetOrNew(name string) (Key, bool) {
	return a.GetOrNewFunc(name)
}

func (a MockAesStore) Store(name string, key []byte) {
	a.StoreFunc(name, key)
}

func (a MockAesStore) Revive(name string) {
	a.ReviveFunc(name)
}

func (a MockAesStore) Stop() {
	a.StopFunc()
}

type Store interface {
	New(name string) Key
	Get(name string) Key
	GetOrNew(name string) (Key, bool)
	Store(name string, key []byte)
	Revive(name string)
	Stop()
}

func New() Store {
	ctx, cancel := context.WithCancel(context.Background())
	a := &AesStore{
		mp:     cache.New(time.Minute*5, time.Minute*30),
		ctx:    ctx,
		cancel: cancel,
	}

	return a
}

func (a *AesStore) New(name string) Key {
	key := AesKey{
		KeyBytes: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}
	a.mp.Store(name, key)
	return key
}

func (a *AesStore) Get(name string) Key {
	if v, ok := a.mp.Get(name); ok {
		return v.(AesKey)
	}

	return nil
}

func (a *AesStore) GetOrNew(name string) (Key, bool) {
	key := AesKey{
		KeyBytes: utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte),
	}

	if v, ok := a.mp.StoreOrGet(name, key); ok {
		return v.(AesKey), false
	}

	return key, true
}

func (a *AesStore) Store(name string, key []byte) {
	a.mp.Store(name, AesKey{
		KeyBytes: key,
	})
}

func (a *AesStore) Revive(name string) {
	a.mp.Expire(name, time.Now().Add(time.Minute*30))
}

func (a *AesStore) Stop() {
	a.mp.Stop()
}
