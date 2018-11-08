package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrivateKeyUtils(t *testing.T) {
	priv, _, err := generateRsaKeyPair()
	assert.NoError(t, err)
	privPem := exportRsaPrivateKeyAsPem(priv)
	parsedPriv, err := parseRsaPrivateKeyFromPem(privPem)
	assert.NoError(t, err)
	// parsed private key should match original
	assert.Equal(t, priv, parsedPriv)

	// random byte sequence should not work
	parsedPriv, err = parseRsaPrivateKeyFromPem([]byte{0xf2})
	assert.NotNil(t, err)
	assert.NotEqual(t, priv, parsedPriv)
}

func TestPublicKeyUtils(t *testing.T) {
	_, pub, err := generateRsaKeyPair()
	assert.NoError(t, err)
	pubPem := exportRsaPublicKeyAsPem(pub)
	parsedPub, err := parseRsaPublicKeyFromPem(pubPem)
	assert.NoError(t, err)
	// parsed public key should match original
	assert.Equal(t, pub, parsedPub)

	// random byte sequence should not work
	parsedPub, err = parseRsaPublicKeyFromPem([]byte{0xf2, 0x23, 0xab})
	assert.NotNil(t, err)
	assert.NotEqual(t, pub, parsedPub)
}
