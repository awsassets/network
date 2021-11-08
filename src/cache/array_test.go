package cache

import (
	"testing"
	"time"

	"github.com/disembark/network/src/utils"
	"github.com/stretchr/testify/assert"
)

func Test_Array(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"

	cache := NewArray(time.Millisecond*500, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)
	cache.Store(key, key_2_2, value2)

	ret, ok := cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value, ret, "The value is in correct order")

	time.Sleep(time.Millisecond * 500)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is in correct order")

	rets, ok := cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, 1, len(rets), "There is only 1 result")
	assert.Equal(t, value2, rets[0], "The value is in correct order")

	cache.Delete(key, key_2_1)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is in correct order")

	cache.Delete(key, key_2_2)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, false, ok, "The value exists")
	assert.Equal(t, nil, ret, "The value is nil")
}

func Test_Array2(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"

	cache := NewArray(time.Millisecond*5, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)
	cache.Store(key, key_2_2, value2)

	ret, ok := cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value, ret, "The value is in correct order")

	time.Sleep(time.Millisecond * 500)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is in correct order")

	rets, ok := cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, 1, len(rets), "There is only 1 result")
	assert.Equal(t, value2, rets[0], "The value is in correct order")

	cache.Delete(key, key_2_1)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is in correct order")

	cache.Delete(key, key_2_2)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, false, ok, "The value exists")
	assert.Equal(t, nil, ret, "The value is nil")
}

func Test_Array3(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"

	cache := NewArray(time.Millisecond*5, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)
	cache.Store(key, key_2_2, value2)

	cache.Delete(key, "")

	ret, ok := cache.GetFirst(key)
	assert.Equal(t, false, ok, "The value exists")
	assert.Equal(t, nil, ret, "The value is nil")
}

func Test_Array4(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"
	value3 := "xd2"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"
	key_2_3 := "kappa2"

	cache := NewArray(time.Millisecond*500, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_3, value3)

	rets, ok := cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, 2, len(rets), "There are only 2 values")
	assert.Equal(t, value2, rets[0], "They are in the correct order")
	assert.Equal(t, value3, rets[1], "They are in the correct order")

	ret, ok := cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is nil")

	time.Sleep(time.Millisecond * 500)

	rets, ok = cache.Get(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, 1, len(rets), "There are only 1 value")
	assert.Equal(t, value3, rets[0], "They are in the correct order")

	time.Sleep(time.Millisecond * 500)

	rets, ok = cache.Get(key)
	assert.Equal(t, false, ok, "The value exists")
	assert.Equal(t, 0, len(rets), "There are only 0 values")
}

func Test_Array5(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"
	value3 := "xd2"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"
	key_2_3 := "kappa2"

	cache := NewArray(time.Millisecond*500, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_3, value3)

	ret, ok := cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value2, ret, "The value is nil")

	time.Sleep(time.Millisecond * 500)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, true, ok, "The value exists")
	assert.Equal(t, value3, ret, "They are in the correct order")

	time.Sleep(time.Millisecond * 500)

	ret, ok = cache.GetFirst(key)
	assert.Equal(t, false, ok, "The value exists")
	assert.Equal(t, nil, ret, "The value is nil")
}

func Test_Array6(t *testing.T) {
	value := interface{}(utils.Int64Pointer(123))
	value2 := "xd"
	value3 := "xd2"

	key := "test"
	key_2_1 := "abc"
	key_2_2 := "kappa"
	key_2_3 := "kappa2"

	cache := NewArray(time.Millisecond*500, time.Second)
	defer cache.Stop()
	defer cache.Stop()

	cache.Store(key, key_2_1, value)

	time.Sleep(time.Millisecond * 500)

	cache.Store(key, key_2_2, value2)

	cache.Store(key, key_2_3, value3)

	items := cache.Items()
	assert.Equal(t, value, items[key].Items[0].Object, "They are in the correct order")
	assert.Equal(t, value2, items[key].Items[1].Object, "They are in the correct order")
	assert.Equal(t, value3, items[key].Items[2].Object, "They are in the correct order")

	arr := cache.ItemsArray()

	assert.Equal(t, value, arr[0].Items[0].Object, "They are in the correct order")
	assert.Equal(t, value2, arr[0].Items[1].Object, "They are in the correct order")
	assert.Equal(t, value3, arr[0].Items[2].Object, "They are in the correct order")
}
