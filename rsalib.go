package rsa

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
)
/////////////////////////////////////////////////////////////////////////////////////////////////
// PKCS1 Sign create
/////////////////////////////////////////////////////////////////////////////////////////////////
func SignRsaPKCS1 (Priv *rsa.PrivateKey, digest string) ([]byte, error) {

	byteMessage := []byte(digest)
	pssMessage := byteMessage
	newHash := crypto.SHA256
	pssNewHash := newHash.New()

	if _, err := pssNewHash.Write(pssMessage); err != nil {
		return  []byte(""),err
	}
	hashed := pssNewHash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, Priv, newHash, hashed)
	if err != nil {
		return  []byte(""),err
	}

	return  signature, nil
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// PKCS1 Verify sign
/////////////////////////////////////////////////////////////////////////////////////////////////
func VerifyRsaPKCS1 (Pub *rsa.PublicKey, byteSig []byte, digest string) (bool, error) {

	byteMessage := []byte(digest)
	pssMessage := byteMessage
	newHash := crypto.SHA256
	pssNewHash := newHash.New()

	if _, err := pssNewHash.Write(pssMessage); err != nil {
		return  false, err
	}
	hashed := pssNewHash.Sum(nil)

	//Verify Signature
	if err := rsa.VerifyPKCS1v15(Pub, newHash, hashed, byteSig); err != nil {
		return  false, err
	}

	return  true, nil
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// PSS Sign create
/////////////////////////////////////////////////////////////////////////////////////////////////
func SignRsaPss (Priv *rsa.PrivateKey, digest string) ([]byte, error) {

	var opts rsa.PSSOptions

	byteMessage := []byte(digest)
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash // for simple example
	pssMessage := byteMessage
	newHash := crypto.SHA256
	pssNewHash := newHash.New()

	if _, err := pssNewHash.Write(pssMessage); err != nil {
		return  []byte(""),err
	}
	hashed := pssNewHash.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, Priv, newHash, hashed, &opts)
	if err != nil {
		return  []byte(""),err
	}

	return  signature, nil
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// PSS Verify sign
/////////////////////////////////////////////////////////////////////////////////////////////////
func VerifyRsaPss (Pub *rsa.PublicKey, byteSig []byte, digest string) (bool, error) {

	var opts rsa.PSSOptions

	byteMessage := []byte(digest)
	opts.SaltLength = rsa.PSSSaltLengthEqualsHash // for simple example
	pssMessage := byteMessage
	newHash := crypto.SHA256
	pssNewHash := newHash.New()

	if _, err := pssNewHash.Write(pssMessage); err != nil {
		return  false, err
	}
	hashed := pssNewHash.Sum(nil)

	//Verify Signature
	if err := rsa.VerifyPSS(Pub, newHash, hashed, byteSig, &opts); err != nil {
		return  false, err
	}

	return  true, nil
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// RSA encrypt digest
/////////////////////////////////////////////////////////////////////////////////////////////////
func EncryptRSA(Pub *rsa.PublicKey, dgst string) ([]byte, error) {

	message := []byte(dgst)
	label := []byte("")
	hash := sha256.New()

	if encryptText, err := rsa.EncryptOAEP(hash, rand.Reader, Pub, message, label); err == nil {
		return encryptText, err
	} else {
		return []byte(""),err
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// RSA decript digest
/////////////////////////////////////////////////////////////////////////////////////////////////
func DecriptRSA(Priv *rsa.PrivateKey, message []byte)  ([]byte, error)  {

	label := []byte("")
	hash := sha256.New()

	if decriptText, err := rsa.DecryptOAEP(hash, rand.Reader, Priv, message, label); err == nil {
		return decriptText, err
	} else {
		return []byte(""),err
	}
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// generate RSA pair keys
/////////////////////////////////////////////////////////////////////////////////////////////////
func GeneratePairKeys(path string, name string) error {

	var err error
	// Generate RSA Keys
	if PrivateKey, err := rsa.GenerateKey(rand.Reader, 2048); err == nil {
		PublicKey := &PrivateKey.PublicKey

		if err = SavePrivateKey(path + name + "PrivateKey.pem", PrivateKey); err == nil {
			err = SavePublicKey(path + name + "PublicKey.pub", PublicKey)
		}
	}
	return err
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// load Private Key from file
/////////////////////////////////////////////////////////////////////////////////////////////////
func SavePublicKey(fName string, pubkey *rsa.PublicKey) error {

	var err error
	if pemfile, err := os.Create(fName); err == nil {
		defer func() {
			err = pemfile.Close()
		}()

		//converts an RSA public key to PKCS#1, ASN.1 DER form.
		var pemkey = &pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pubkey),
		}
		err = pem.Encode(pemfile, pemkey)
	}
	return  err
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// save Private Key from file
/////////////////////////////////////////////////////////////////////////////////////////////////
func SavePrivateKey(fName string, key *rsa.PrivateKey) error {

	var err error
	if outFile, err := os.Create(fName); err == nil {
		defer func() {
			 err = outFile.Close()
		}()

		//converts a private key to ASN.1 DER encoded form.
		var privateKey = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
		err = pem.Encode(outFile, privateKey)
	}
	return  err
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// load Private Key from file
/////////////////////////////////////////////////////////////////////////////////////////////////
func LoadPrivateKey(fileName string)   (*rsa.PrivateKey, error)  {

	var err error
	if privateKeyFile, err := os.Open(fileName); err == nil {
		if pemFileInfo, err := privateKeyFile.Stat(); err == nil {

			size  := pemFileInfo.Size()
			pemBytes := make([]byte, size)
			buffer := bufio.NewReader(privateKeyFile)

			if _, err = buffer.Read(pemBytes); err == nil {
				data,_ := pem.Decode([]byte(pemBytes))
				if err = privateKeyFile.Close(); err == nil {
					if privateKeyFileImported, err := x509.ParsePKCS1PrivateKey(data.Bytes); err == nil {

						return privateKeyFileImported, nil
					}
				}
			}
		}
	}
	return nil, err
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// load Public Key from file
/////////////////////////////////////////////////////////////////////////////////////////////////
func LoadPublicKey(fileName string)  (*rsa.PublicKey, error) {

	var err error
	if publicKeyFile, err := os.Open(fileName); err == nil {
		if pemFileInfo, err := publicKeyFile.Stat(); err == nil {

			size  := pemFileInfo.Size()
			pemBytes := make([]byte, size)
			buffer := bufio.NewReader(publicKeyFile)

			if _, err = buffer.Read(pemBytes); err == nil {
				data,_ := pem.Decode([]byte(pemBytes))
				if err = publicKeyFile.Close(); err == nil {
					if publicKeyFileImported, err := x509.ParsePKCS1PublicKey(data.Bytes); err == nil {

						return publicKeyFileImported, nil
					}
				}
			}
		}
	}
	return nil, err
}
/////////////////////////////////////////////////////////////////////////////////////////////////
// is File Exists ?
/////////////////////////////////////////////////////////////////////////////////////////////////
func FileExists(filename string) bool {

	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
} 
