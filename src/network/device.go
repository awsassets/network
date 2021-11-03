package network

import "io"

type Device interface {
	io.Reader
	io.Writer

	Name() string
}
