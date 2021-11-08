package cache

import (
	"sync"
	"time"
)

type Cache interface {
	Stop()
	Store(key string, value interface{})
	Expire(key string, t time.Time)
	StoreExpiry(key string, value interface{}, expiry time.Time)
	Get(key string) (interface{}, bool)
	StoreOrGet(key string, value interface{}) (interface{}, bool)
	StoreOrGetExpire(key string, value interface{}, expiry time.Time) (interface{}, bool)
	Merge(item CacheItem) (interface{}, bool)
	Delete(key string)
	GetDelete(key string) (interface{}, bool)
	ItemsArray() []CacheItem
	Items() map[string]CacheItem
}

type cache struct {
	dirty   sync.Map
	mtx     sync.Mutex
	cleanup time.Duration
	expire  time.Duration
	isDone  bool
	doneCh  chan struct{}
}

type CacheItem struct {
	Key    string
	Object interface{}
	Expiry time.Time
}

func (c CacheItem) Expired() bool {
	return !c.Expiry.IsZero() && time.Now().After(c.Expiry)
}

func New(cleanup time.Duration, expire time.Duration) Cache {
	if cleanup < 0 {
		cleanup = 0
	}
	if expire < 0 {
		expire = 0
	}

	c := &cache{
		cleanup: cleanup,
		expire:  expire,
		doneCh:  make(chan struct{}),
	}
	if cleanup != 0 {
		go c.worker()
	}

	return c
}

func (c *cache) Stop() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isDone {
		return
	}

	c.isDone = true
	close(c.doneCh)
}

func (c *cache) Store(key string, value interface{}) {
	expiry := time.Time{}
	if c.expire != 0 {
		expiry = time.Now().Add(c.expire)
	}

	c.StoreExpiry(key, value, expiry)
}

func (c *cache) Expire(key string, t time.Time) {
	if v, ok := c.dirty.Load(key); ok {
		item := v.(CacheItem)
		item.Expiry = t
		c.dirty.Store(key, item)
	}
}

func (c *cache) StoreExpiry(key string, value interface{}, expiry time.Time) {
	if expiry.Before(time.Now()) {
		return
	}

	c.dirty.Store(key, CacheItem{
		Key:    key,
		Object: value,
		Expiry: expiry,
	})
}

func (c *cache) Get(key string) (interface{}, bool) {
	i, ok := c.dirty.Load(key)
	if !ok {
		return nil, false
	}

	item := i.(CacheItem)
	if item.Expired() {
		c.dirty.Delete(key)
		return nil, false
	}

	return item.Object, true
}

func (c *cache) StoreOrGet(key string, value interface{}) (interface{}, bool) {
	expiry := time.Time{}
	if c.expire != 0 {
		expiry = time.Now().Add(c.expire)
	}

	return c.StoreOrGetExpire(key, value, expiry)
}

func (c *cache) StoreOrGetExpire(key string, value interface{}, expiry time.Time) (interface{}, bool) {
	i, ok := c.dirty.LoadOrStore(key, CacheItem{
		Key:    key,
		Object: value,
		Expiry: expiry,
	})
	if !ok {
		return value, false
	}

	item := i.(CacheItem)
	if item.Expired() {
		c.dirty.Store(key, CacheItem{
			Key:    key,
			Object: value,
			Expiry: expiry,
		})
		return value, false
	}

	return item.Object, true
}

func (c *cache) Merge(item CacheItem) (interface{}, bool) {
	old, load := c.dirty.LoadOrStore(item.Key, item)
	if load {
		oldItem := old.(CacheItem)
		if !oldItem.Expiry.IsZero() && oldItem.Expiry.Before(item.Expiry) {
			c.dirty.Store(item.Key, item)
			return oldItem.Object, true
		}
	}

	return nil, false
}

func (c *cache) clean() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(CacheItem)
		if item.Expired() {
			c.dirty.Delete(key)
		}

		return true
	})
}

func (c *cache) worker() {
	tick := time.NewTicker(c.cleanup)
	for {
		select {
		case <-c.doneCh:
			return
		case <-tick.C:
			c.clean()
		}
	}
}

func (c *cache) Delete(key string) {
	c.dirty.Delete(key)
}

func (c *cache) GetDelete(key string) (interface{}, bool) {
	if v, ok := c.dirty.LoadAndDelete(key); ok {
		return v.(CacheItem).Object, true
	}

	return nil, false
}

func (c *cache) ItemsArray() []CacheItem {
	items := []CacheItem{}
	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(CacheItem)
		if item.Expired() {
			return true
		}

		items = append(items, item)
		return true
	})

	return items
}

func (c *cache) Items() map[string]CacheItem {
	items := map[string]CacheItem{}
	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(CacheItem)
		if item.Expired() {
			return true
		}

		items[key.(string)] = item
		return true
	})

	return items
}
