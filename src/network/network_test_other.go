//go:build !windows && !linux
// +build !windows,!linux

package network

import "testing"

func Test_Linux(t *testing.T) {
	t.Fatal("not supported")
}
