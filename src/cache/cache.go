package cache

import (
	"sync"
	"time"
)

type Cache struct {
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

func New(cleanup time.Duration, expire time.Duration) *Cache {
	if cleanup < 0 {
		cleanup = 0
	}
	if expire < 0 {
		expire = 0
	}

	c := &Cache{
		cleanup: cleanup,
		expire:  expire,
		doneCh:  make(chan struct{}),
	}
	if cleanup != 0 {
		go c.worker()
	}

	return c
}

func (c *Cache) Stop() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isDone {
		return
	}

	c.isDone = true
	close(c.doneCh)
}

func (c *Cache) Store(key string, value interface{}) {
	expiry := time.Time{}
	if c.expire != 0 {
		expiry = time.Now().Add(c.expire)
	}

	c.dirty.Store(key, CacheItem{
		Key:    key,
		Object: value,
		Expiry: expiry,
	})
}

func (c *Cache) StoreExpiry(key string, value interface{}, expiry time.Time) {
	if expiry.Before(time.Now()) {
		return
	}

	c.dirty.Store(key, CacheItem{
		Key:    key,
		Object: value,
		Expiry: expiry,
	})
}

func (c *Cache) Get(key string) (interface{}, bool) {
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

func (c *Cache) Merge(item CacheItem) (interface{}, bool) {
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

func (c *Cache) clean() {
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

func (c *Cache) worker() {
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

func (c *Cache) Delete(key string) {
	c.dirty.Delete(key)
}

func (c *Cache) ItemsArray() []CacheItem {
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

func (c *Cache) Items() map[string]CacheItem {
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
