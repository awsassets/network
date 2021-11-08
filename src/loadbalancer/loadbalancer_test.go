package loadbalancer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Loadbalancer(t *testing.T) {
	items := []interface{}{1, 2, 3, 4, 5}
	lb := New(items...)

	assert.Equal(t, items[0], lb.GetItem(0), "Order is preserved")
	assert.Equal(t, items[1], lb.GetItem(1), "Order is preserved")
	assert.Equal(t, items[2], lb.GetItem(2), "Order is preserved")
	assert.Equal(t, items[3], lb.GetItem(3), "Order is preserved")
	assert.Equal(t, items[4], lb.GetItem(4), "Order is preserved")
	assert.Equal(t, items[0], lb.GetItem(5), "Order is preserved")

	assert.Equal(t, items[0], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[1], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[2], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[3], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[4], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[0], lb.GetNext(), "Order is preserved")

	for i, v := range lb.GetItems() {
		assert.Equal(t, items[i], v, "Order is preserved")
	}

	lb.AddItem("pog")

	assert.Equal(t, items[1], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[2], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[3], lb.GetNext(), "Order is preserved")
	assert.Equal(t, items[4], lb.GetNext(), "Order is preserved")
	assert.Equal(t, "pog", lb.GetNext(), "Order is preserved")
}
