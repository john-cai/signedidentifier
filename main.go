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
	DefaultKeypath      = "/.ssh"
	DefaultPrivFilename = "id_rsa"
	DefaultPubFilename  = "id_rsa.pub"
)

type Response struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PublicKey string `json:"pubkey"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("wrong number of arguments")
	}
	in := os.Args[1]
	if len(in) > 250 {
		log.Fatal("input must be less than 250 characters")
	}

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

	// if keylocation doesn't exist, create the folder and the keys
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
