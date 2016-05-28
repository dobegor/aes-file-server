package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Cryptos is an interface to wrap encryption/decryption process of binary data.
type Cryptos interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// Cryptos implementation using AES algorithm with cipher feedback (CFB).
type aes_cryptos struct {
	block cipher.Block
}

// Key should be either 16, 24 or 32 bytes long to fit AES-128, AES-192, AES-256.
func NewAESCryptos(key []byte) (Cryptos, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return aes_cryptos{b}, nil
}

// Encrypts data.
func (c aes_cryptos) Encrypt(data []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(data))

	// Generate random Initialization Vector
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(c.block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))
	return ciphertext, nil
}

// Decrypts data.
func (c aes_cryptos) Decrypt(data []byte) ([]byte, error) {
	// Data smaller than a block size can't be decrypted
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(c.block, iv)
	cfb.XORKeyStream(data, data)
	return data, nil
}
