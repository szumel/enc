package enc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

//@TODO refactor
//Return private key and related public key in PEM format
func GenerateKeyPair() (PemKeyPair, error) {
	var keyPair PemKeyPair
	reader := rand.Reader
	size := 2048

	pKey, err := rsa.GenerateKey(reader, size)

	if err != nil {
		return keyPair, err
	}

	pKeyCipherBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pKey),
	}

	pKeyEncodingBuff := bytes.Buffer{}
	err = pem.Encode(&pKeyEncodingBuff, &pKeyCipherBlock)
	if err != nil {
		return keyPair, err
	}

	pubKey := pKey.PublicKey
	asn1Bytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	pubKeyCipherBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pubKeyEncodingBuff := bytes.Buffer{}
	err = pem.Encode(&pubKeyEncodingBuff, &pubKeyCipherBlock)

	if err != nil {
		return keyPair, err
	}

	keyPair.PrivateKey = pKeyEncodingBuff.String()
	keyPair.PublicKey = pubKeyEncodingBuff.String()

	return keyPair, nil
}

type PemKeyPair struct {
	PrivateKey string
	PublicKey  string
}

//@TODO refactor
//Encrypt given text and label with given public key in OAEP RSA format
func Encrypt(text string, publicKey string) ([]byte, error) {
	var encrypted []byte
	block, _ := pem.Decode([]byte(publicKey))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return encrypted, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return encrypted, errors.New("Could not make assertion from public key to rsa.PublicKey")
	}

	sha512 := sha512.New()
	rand := rand.Reader

	encrypted, err = rsa.EncryptOAEP(sha512, rand, rsaPubKey, []byte(text), []byte{})

	if err != nil {
		return encrypted, err
	}

	return encrypted, err
}

//@TODO refactor
//Decrypt given OAEP RSA encrypted message with given private key
func Decrypt(encrypted []byte, privateKey string) ([]byte, error) {
	var decrypted []byte
	block, _ := pem.Decode([]byte(privateKey))
	pKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return decrypted, nil
	}

	sha512 := sha512.New()
	decrypted, err = rsa.DecryptOAEP(sha512, rand.Reader, pKey, encrypted, []byte{})

	if err != nil {
		return decrypted, err
	}

	return decrypted, nil
}