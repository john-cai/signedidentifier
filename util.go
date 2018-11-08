package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// generateRsaKeyPair generates a public/private keypair
func generateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// exportRsaPrivateKeyAsPem takes an *rsa.PrivateKey and returns a byte slice of the PEM representation of the key
func exportRsaPrivateKeyAsPem(privkey *rsa.PrivateKey) []byte {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return privkeyPem
}

// exportRsaPublicKeyAsPem takes an *rsa.PublicKey and returns a byte slice of the PEM representation of the key
func exportRsaPublicKeyAsPem(pubkey *rsa.PublicKey) []byte {
	pubkeyBytes := x509.MarshalPKCS1PublicKey(pubkey)
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)
	return pubkeyPem
}

// parseRsaPrivateKeyFromPem takes a byte slice and parses it as a private key
func parseRsaPrivateKeyFromPem(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// parseRsaPublicKeyFromPem takes a byte slice and parses it as a public key
func parseRsaPublicKeyFromPem(b []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}
