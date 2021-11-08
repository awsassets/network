package utils

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TLS(t *testing.T) {
	publicKeyCA := "-----BEGIN CERTIFICATE-----\nMIIBejCCASGgAwIBAgICB+MwCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTEwMTMwMTMzNDNaFw0zMTEwMTMwMTMzNDNaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8IG2tuuHfO0va\n/ZzgQPz7tLpvPboGlHyD2+ge3QF8zUGdNT71JEqCW2di2NfbGT2ZRih2DrtQF9KG\ndTR2GXXBo2EwXzAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFInScQHTxhg9iIwk\nPzwykqr40+MQMAoGCCqGSM49BAMCA0cAMEQCICGdaNA1gVBZovier9GSi+47Fauw\nuq/hPXwvNCZ3uEK7AiANKMyLRNt+7IWVXIiD+ZN6Ya4NnQITm58nJ9FhTmChcQ==\n-----END CERTIFICATE-----"

	tlsConfig := TlsConfig(publicKeyCA)

	publicKey := []byte("-----BEGIN CERTIFICATE-----\nMIIBWjCCAQGgAwIBAgICBnowCgYIKoZIzj0EAwIwFTETMBEGA1UEChMKRGlzZW1i\nYXJrLjAeFw0yMTExMDIxOTUwNDdaFw0zMTExMDIxOTUwNDdaMBUxEzARBgNVBAoT\nCkRpc2VtYmFyay4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQW80iKWVLNiTHN\nqYbq+PfAx7QfPmW5lEWg3TzWA8XP/Cf7s/VOQlkZnnnQDV4e/c/z++HU0f5BQAfm\nlCMQakiRo0EwPzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMA4GA1UdDgQHBAUBAgMEBjAKBggqhkjOPQQDAgNHADBEAiAHltU3\nv83CHp9N1PUqrLSTQLHW5uiIICqmY2ljt4jGUwIgDaAS3CkadQzAtCfHsRr4Lpn/\nG5I4wm+1RTQWyd6uUYQ=\n-----END CERTIFICATE-----")
	privKey := []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSkJwsKlGoGi9pdOu\nmM8zVmD/gvQyPxluhYxdkZSunvuhRANCAAQW80iKWVLNiTHNqYbq+PfAx7QfPmW5\nlEWg3TzWA8XP/Cf7s/VOQlkZnnnQDV4e/c/z++HU0f5BQAfmlCMQakiR\n-----END PRIVATE KEY-----")

	cert, err := tls.X509KeyPair(publicKey, privKey)
	assert.ErrorIs(t, err, nil, "the public and private key are valid")

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	assert.ErrorIs(t, err, nil, "there is a valid listener")
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		assert.ErrorIs(t, err, nil, "the connection was valid")
		_, err = conn.Write([]byte("hello"))
		assert.ErrorIs(t, err, nil, "the connection was written")
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), tlsConfig)
	assert.ErrorIs(t, err, nil, "the connection was valid")

	data := make([]byte, 100)
	n, err := conn.Read(data)
	assert.ErrorIs(t, err, nil, "the connection was read")
	assert.Equal(t, "hello", string(data[:n]), "The message is correct")
}
