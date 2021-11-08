package event_store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Event(t *testing.T) {
	events := New()
	defer events.Stop()

	event := "abc"

	assert.Equal(t, false, events.Register(event), "The event is registered")
	assert.Equal(t, true, events.Register(event), "The event is not registered")
}
