package helpers

import (
	"encoding/hex"
	"testing"

	"github.com/disembark/network/src/configure"
	"github.com/disembark/network/src/utils"
	"github.com/stretchr/testify/assert"
)

func Test_SSL(t *testing.T) {
	config := &configure.Config{
		TokenKey: hex.EncodeToString(utils.OrPanic(utils.GenerateRandomBytes(32))[0].([]byte)),
	}
	GenerateCaTls(config)

	_, err := GenerateNode(config, "node")
	assert.ErrorIs(t, err, nil, "Node Error is nil")

	_, err = GenerateSignal(config, "signal")
	assert.ErrorIs(t, err, nil, "Signal Error is nil")

	_, err = GenerateRelayServer(config, "relay")
	assert.ErrorIs(t, err, nil, "Relay Server Error is nil")

	_, err = GenerateRelayClient(config, "relay")
	assert.ErrorIs(t, err, nil, "Relay Server Error is nil")

	tkn, err := GenerateClientJoinToken(config, configure.ModeNode, "node")
	assert.ErrorIs(t, err, nil, "Token generation is nil")

	pl, err := VerifyClientJoinToken(config, tkn)
	assert.ErrorIs(t, err, nil, "No error on verify token")

	assert.Equal(t, pl.Name, "node", "Name is node")
	assert.Equal(t, pl.Mode, configure.ModeNode, "Mode is node")
}
