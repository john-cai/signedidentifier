package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

const (
	// DefaultKeypath is the default path for where the keys will be stored on the filesystem
	DefaultKeypath = "/.ssh"
	// DefaultPrivFilename is the default filename for the private rsa key
	DefaultPrivFilename = "id_rsa"
	// DefaultPubFilename is the default filename for the public rsa key
	DefaultPubFilename = "id_rsa.pub"
)

// Response is how the signature is returned
type Response struct {
	// Message is the original input string
	Message string `json:"message"`
	// Signature is the base64 encoded signature
	Signature string `json:"signature"`
	// PublicKey is the PEM representation of the public key
	PublicKey string `json:"pubkey"`
}

func main() {
	// check that only 1 argument was passed in
	if len(os.Args) != 2 {
		log.Fatal("wrong number of arguments")
	}
	in := os.Args[1]

	// validate the input length
	if len(in) > 250 {
		log.Fatal("input must be less than 250 characters")
	}

	// read environment variables for the key path, and key filenames
	keyLocation := os.Getenv("KEYPATH")
	if keyLocation == "" {
		keyLocation = DefaultKeypath
	}
	pubFilename := os.Getenv("PUBKEY_FILENAME")
	privFilename := os.Getenv("PRIVKEY_FILENAME")
	if pubFilename == "" {
		pubFilename = DefaultPubFilename
	}
	if privFilename == "" {
		privFilename = DefaultPrivFilename
	}

	// if the key location doesn't exist, create the folder and the keys
	var priv *rsa.PrivateKey
	var pub *rsa.PublicKey
	if _, err := os.Stat(keyLocation); os.IsNotExist(err) {
		if err = os.Mkdir(keyLocation, os.ModeDir|0644); err != nil {
			log.Fatalf("could not create directory for keys: %v", err)
		}
		// generate keypair and save it as pem files
		priv, pub, err = generateRsaKeyPair()
		if err != nil {
			log.Fatalf("error when generating rsa keypair: %v", err)
		}
		if err = ioutil.WriteFile(fmt.Sprintf("%s/%s", keyLocation, privFilename), exportRsaPrivateKeyAsPem(priv), 0600); err != nil {
			log.Fatalf("could not write file for private key: %v", err)
		}
		if err = ioutil.WriteFile(fmt.Sprintf("%s/%s", keyLocation, pubFilename), exportRsaPublicKeyAsPem(pub), 0644); err != nil {
			log.Fatalf("could not write file for public key: %v", err)
		}
	}
	// if necessary, read the private and public key files
	if priv == nil {
		privFile, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", keyLocation, privFilename))
		if err != nil {
			log.Fatalf("could not read private pem file: %v", err)
		}
		if priv, err = parseRsaPrivateKeyFromPem(privFile); err != nil {
			log.Fatalf("could not parse private pem file: %v", err)
		}
	}
	if pub == nil {
		pubFile, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", keyLocation, pubFilename))
		if err != nil {
			log.Fatalf("could not read public pem file: %v", err)
		}
		if pub, err = parseRsaPublicKeyFromPem(pubFile); err != nil {
			log.Fatalf("could not parse public pem file: %v", err)
		}
	}

	// calculate the signature
	hashed := sha256.Sum256([]byte(in))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Error from signing: %v", err)
	}
	response := Response{
		Message:   in,
		Signature: base64.StdEncoding.EncodeToString(signature),
		PublicKey: string(exportRsaPublicKeyAsPem(pub)),
	}
	if err := json.NewEncoder(os.Stdout).Encode(&response); err != nil {
		log.Fatalf("could not encode response: %v", err)
	}
	os.Exit(0)
}
