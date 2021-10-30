package cache

import (
	"sync"
	"time"
)

type CacheArray struct {
	dirty   sync.Map
	mtx     sync.Mutex
	cleanup time.Duration
	expire  time.Duration
	isDone  bool
	doneCh  chan struct{}
}

type CacheArrayItem struct {
	Key         string
	Items       []CacheItem
	mtx         *sync.Mutex
	deleted     bool
	firstExpire time.Time
}

func (c CacheArrayItem) Expired() bool {
	return !c.firstExpire.IsZero() && time.Now().After(c.firstExpire)
}

func NewArray(cleanup time.Duration, expire time.Duration) *CacheArray {
	if cleanup < 0 {
		cleanup = 0
	}
	if expire < 0 {
		expire = 0
	}

	c := &CacheArray{
		cleanup: cleanup,
		expire:  expire,
		doneCh:  make(chan struct{}),
	}
	if cleanup != 0 {
		go c.worker()
	}

	return c
}

func (c *CacheArray) clean() {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(*CacheArrayItem)
		item.mtx.Lock()
		defer item.mtx.Unlock()

		if !item.Expired() {
			return true
		}

		item.firstExpire = time.Time{}
		newItems := make([]CacheItem, len(item.Items))
		i := 0
		for _, v := range item.Items {
			if !v.Expired() {
				newItems[i] = v
				i++

				if !v.Expiry.IsZero() && (item.firstExpire.IsZero() || item.firstExpire.After(v.Expiry)) {
					item.firstExpire = v.Expiry
				}
			}
		}

		if i == 0 {
			c.dirty.Delete(key)
			item.deleted = true
		} else {
			item.Items = newItems[:i]
		}

		return true
	})
}

func (c *CacheArray) worker() {
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

func (c *CacheArray) Stop() {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.isDone {
		return
	}

	c.isDone = true
	close(c.doneCh)
}

func (c *CacheArray) Store(key string, secondKey string, value interface{}) {
	expiry := time.Time{}
	if c.expire != 0 {
		expiry = time.Now().Add(c.expire)
	}

	c.StoreExpiry(key, secondKey, value, expiry)
}

func (c *CacheArray) StoreExpiry(key string, secondKey string, value interface{}, expiry time.Time) {
	if expiry.Before(time.Now()) {
		return
	}

	v, _ := c.dirty.LoadOrStore(key, &CacheArrayItem{
		Key: key,
		mtx: &sync.Mutex{},
	})

	item := v.(*CacheArrayItem)
	item.mtx.Lock()
	defer item.mtx.Unlock()
	if item.deleted {
		c.StoreExpiry(key, secondKey, value, expiry)
		return
	}

	newItems := make([]CacheItem, len(item.Items)+1)
	i := 0
	found := false
	item.firstExpire = time.Time{}

	for _, v := range item.Items {
		if secondKey != "" && v.Key == secondKey {
			// we must replace this item in the array
			newItems[i] = CacheItem{
				Key:    secondKey,
				Object: value,
				Expiry: expiry,
			}
			found = true
			i++
			if !expiry.IsZero() && (item.firstExpire.IsZero() || item.firstExpire.After(expiry)) {
				item.firstExpire = expiry
			}
		} else if !v.Expired() {
			newItems[i] = v
			i++

			if !v.Expiry.IsZero() && (item.firstExpire.IsZero() || item.firstExpire.After(v.Expiry)) {
				item.firstExpire = v.Expiry
			}
		}
	}

	if !found {
		newItems[i] = CacheItem{
			Key:    secondKey,
			Object: value,
			Expiry: expiry,
		}
		i++
	}

	item.Items = newItems[:i]
}

func (c *CacheArray) Get(key string) ([]interface{}, bool) {
	i, ok := c.dirty.Load(key)
	if !ok {
		return nil, false
	}

	item := i.(*CacheArrayItem)
	item.mtx.Lock()
	defer item.mtx.Unlock()
	if item.deleted {
		return c.Get(key)
	}

	if !item.firstExpire.IsZero() && item.firstExpire.Before(time.Now()) {
		// we have to do a clean up on this
		newItems := make([]CacheItem, len(item.Items))
		i := 0
		item.firstExpire = time.Time{}
		for _, v := range item.Items {
			if !v.Expired() {
				newItems[i] = v
				i++
				if !v.Expiry.IsZero() && (item.firstExpire.IsZero() || item.firstExpire.After(v.Expiry)) {
					item.firstExpire = v.Expiry
				}
			}
		}

		if i == 0 {
			c.dirty.Delete(key)
			item.deleted = true
			return nil, false
		} else {
			item.Items = newItems[:i]
		}
	}

	arr := make([]interface{}, len(item.Items))
	for i, v := range item.Items {
		arr[i] = v.Object
	}

	return arr, true
}

func (c *CacheArray) GetFirst(key string) (interface{}, bool) {
	i, ok := c.dirty.Load(key)
	if !ok {
		return nil, false
	}

	item := i.(*CacheArrayItem)
	item.mtx.Lock()
	defer item.mtx.Unlock()
	if item.deleted {
		return c.GetFirst(key)
	}

	if !item.firstExpire.IsZero() && item.firstExpire.Before(time.Now()) {
		// we have to do a clean up on this
		newItems := make([]CacheItem, len(item.Items))
		i := 0
		item.firstExpire = time.Time{}
		for _, v := range item.Items {
			if !v.Expired() {
				newItems[i] = v
				i++
				if !v.Expiry.IsZero() && (item.firstExpire.IsZero() || item.firstExpire.After(v.Expiry)) {
					item.firstExpire = v.Expiry
				}
			}
		}

		if i == 0 {
			c.dirty.Delete(key)
			item.deleted = true
			return nil, false
		} else {
			item.Items = newItems[:i]
		}
	}

	return item.Items[0].Object, true
}

func (c *CacheArray) Delete(key string, secondKey string) {
	if secondKey == "" {
		if v, ok := c.dirty.LoadAndDelete(key); ok {
			item := v.(*CacheArrayItem)
			item.deleted = true
		}
		return
	}

	v, ok := c.dirty.Load(key)
	if !ok {
		return
	}

	item := v.(*CacheArrayItem)
	item.mtx.Lock()
	defer item.mtx.Unlock()
	if item.deleted {
		c.Delete(key, secondKey)
		return
	}

	if len(item.Items) == 1 {
		if item.Items[0].Key == secondKey {
			item.deleted = true
			c.dirty.Delete(key)
		}
		return
	}

	for i, v := range item.Items {
		if v.Key == secondKey {
			for i2 := i + 1; i2 < len(item.Items); i2++ {
				item.Items[i] = item.Items[i2]
				i++
			}
			item.Items = item.Items[:len(item.Items)-1]
			break
		}
	}
}

func (c *CacheArray) ItemsArray() []CacheArrayItem {
	items := []CacheArrayItem{}
	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(*CacheArrayItem)

		item.mtx.Lock()
		defer item.mtx.Unlock()
		if item.deleted {
			return true
		}

		if item.Expired() {
			return true
		}

		dummy := CacheArrayItem{
			Key:   item.Key,
			Items: make([]CacheItem, len(item.Items)),
		}

		i := 0
		for _, v := range item.Items {
			if !v.Expired() {
				dummy.Items[i] = v
				i++
			}
		}

		if i == 0 {
			return true
		}

		dummy.Items = dummy.Items[:i]

		items = append(items, dummy)
		return true
	})

	return items
}

func (c *CacheArray) Items() map[string]CacheArrayItem {
	items := map[string]CacheArrayItem{}
	c.dirty.Range(func(key, value interface{}) bool {
		item := value.(*CacheArrayItem)

		item.mtx.Lock()
		defer item.mtx.Unlock()
		if item.deleted {
			return true
		}

		if item.Expired() {
			return true
		}

		dummy := CacheArrayItem{
			Key:   item.Key,
			Items: make([]CacheItem, len(item.Items)),
		}

		i := 0
		for _, v := range item.Items {
			if !v.Expired() {
				dummy.Items[i] = v
				i++
			}
		}

		if i == 0 {
			return true
		}

		dummy.Items = dummy.Items[:i]

		items[key.(string)] = dummy
		return true
	})

	return items
}
