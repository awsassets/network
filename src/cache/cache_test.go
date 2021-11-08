package cache

import (
	"testing"
	"time"

	"github.com/disembark/network/src/utils"
	"github.com/stretchr/testify/assert"
)

func Test_Cache(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	key := "test"

	cache := New(time.Millisecond*500, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, value)

	time.Sleep(time.Millisecond * 500)

	ret, ok := cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value, ret, "The value did not change")

	ret, ok = cache.StoreOrGet(key, 123)
	assert.Equal(t, true, ok, "We didnt store the value")
	assert.Equal(t, value, ret, "The value did not change")

	time.Sleep(time.Second)

	ret, ok = cache.Get(key)
	assert.Equal(t, false, ok, "The value does not exist")
	assert.Equal(t, nil, ret, "The value is nil")

	value = 123

	ret, ok = cache.StoreOrGet(key, value)
	assert.Equal(t, false, ok, "We stored a new value")
	assert.Equal(t, value, ret, "The value did not change")

	ret, ok = cache.GetDelete(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value, ret, "The value did not change")

	ret, ok = cache.Get(key)
	assert.Equal(t, false, ok, "The value does not exist")
	assert.Equal(t, nil, ret, "The value is nil")

	cache.Store(key, value)
	cache.Delete(key)

	ret, ok = cache.Get(key)
	assert.Equal(t, false, ok, "The value does not exist")
	assert.Equal(t, nil, ret, "The value is nil")
}

func Test_Cache2(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	key := "test"

	cache := New(time.Second*5, time.Millisecond*500)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, value)

	time.Sleep(time.Second)

	ret, ok := cache.Get(key)
	assert.Equal(t, false, ok, "The value does not exist")
	assert.Equal(t, nil, ret, "The value is nil")

	cache.Store(key, value)
	cache.Expire(key, time.Now().Add(time.Second*5))

	time.Sleep(time.Second)

	ret, ok = cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value, ret, "The value did not change")

	cache.Expire(key, time.Now())

	value = 123

	ret, ok = cache.StoreOrGet(key, value)
	assert.Equal(t, false, ok, "We stored a new value")
	assert.Equal(t, value, ret, "The value did not change")
}

func Test_Cache3(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	key := "test"
	key2 := "test2"

	cache := New(time.Second*5, time.Millisecond*500)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, value)
	cache.Store(key2, value)

	cache.Expire(key2, time.Now())

	items := cache.Items()

	assert.Equal(t, value, items[key].Object, "the value is the same")

	arr := cache.ItemsArray()
	for _, v := range arr {
		cache.Merge(v)
	}
}
