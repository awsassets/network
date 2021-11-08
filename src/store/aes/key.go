package aes_store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type AesKey struct {
	KeyBytes []byte
}

type Key interface {
	Key() string
	KeyRaw() []byte
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

func (a AesKey) Key() string {
	return hex.EncodeToString(a.KeyBytes)
}

func (a AesKey) KeyRaw() []byte {
	return a.KeyBytes
}

func (a AesKey) Encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.KeyBytes)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(data[aes.BlockSize:], data[aes.BlockSize:])
	return data, nil
}

func (a AesKey) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.KeyBytes)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)
	return data, nil
}
