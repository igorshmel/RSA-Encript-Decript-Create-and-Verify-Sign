package rsa

import (
	"encoding/base64"
	"fmt"
	"testing"
)

const PATH = ""
const DGST = "the code must be like a piece of music"
const OpenSSLdigest = "nAF0U3vGWHNmb7rQqGsrYXOaEYhvCDL7PCUR7Sueu6FQo7/yYXbTHaeTfpNwzf3s/GYupJvGLVHPej9V55rB6Q=="
const OpenSSLsign = "M4peRW0hsaCGkZAYU7sOL7Q+bI6sXoNzUI0G6JI2QcaflCBRGc9Y+pqGWAZrs7NLboQKhUD/qNSO9bMMX2y8/U3MgUH7VsPxV+X1E0wzw62mlLlZmGO7YI4mdj4jqeAs7q2mdaTz7RUQoR+UDX4OiERh4bB30EMHGu/wbKfcD2h5C+AKtN6G24J3OLb53ZdCShFEsPDUZIKBiLtwBFcOdSF7RF5FEa1NMyB+5O9y8vCOSFEYb3hyRJzIPn/WSS0vx0ce+07xo8WlcqURUAI8o0vxzpOYfmtwgEd5vlceVMpEwK0UDaq5D0fax6Rp5aovKXnJBe+0RxAgiFqrw/o27g=="

func TestRSA(t *testing.T) {

	if FileExists(PATH + "onePrivateKey.pem") {
		// Load rsa keys
		if Priv, err := LoadPrivateKey(PATH + "onePrivateKey.pem"); err == nil {
			if Pub, err := LoadPublicKey(PATH + "onePublicKey.pub"); err == nil {

				// Encrypt digest
				if encryptText, err := EncryptRSA(Pub, DGST); err == nil {
					base64EncryptText := base64.StdEncoding.EncodeToString(encryptText)
					fmt.Printf("base64EncryptText: \n%s \n\n", base64EncryptText)

					// Decode digest
					if byteEncryptText, err := base64.StdEncoding.DecodeString(base64EncryptText); err == nil {
						if byteDecriptText, err := DecriptRSA(Priv, byteEncryptText); err == nil {
							decriptText := string(byteDecriptText)
							fmt.Printf("Success!!! message: %s \n", decriptText)
						}
					} else {
						fmt.Printf("Error base64 DecodeString: %s \n", err)
					}
				} else {
					fmt.Printf("Error encrypt RSA: %s \n", err)

				}

				// Create Sign RSA Pss
				sig,err := SignRsaPss(Priv,DGST)
				if err != nil {
					fmt.Printf("Error signRsaPss: %s \n", err)
				}
				// test base64 Encode Decode
				base64Sig := base64.StdEncoding.EncodeToString(sig)
				byteSig, err := base64.StdEncoding.DecodeString(base64Sig)
				if err != nil {
					fmt.Printf("Error base64 DecodeString: %s \n", err)
				}

				// Verify Sign RSA Pss
				ok,err := VerifyRsaPss(Pub,byteSig,DGST)
				if err != nil {
					fmt.Printf("Error VerifyRsaPss: %s \n", err)
				} else {
					if ok {
						fmt.Println("!!! Verify Succ !!!")
					} else {
						fmt.Println("Verify NOT Succ")
					}
				}

				// if sign create with openssl
				// echo -n 'nAF0U3vGWHNmb7rQqGsrYXOaEYhvCDL7PCUR7Sueu6FQo7/yYXbTHaeTfpNwzf3s/GYupJvGLVHPej9V55rB6Q==' | openssl dgst -sign onePrivateKey.pem -sha256 | openssl base64
				OpenSSLsignPKCS1, _ := base64.StdEncoding.DecodeString(OpenSSLsign)

				// Verify Sign RSA Pss KCS1
				succ, err := VerifyRsaPKCS1(Pub,OpenSSLsignPKCS1,OpenSSLdigest)
				if err != nil {
					fmt.Printf("Error VerifyRsaPss: %s \n", err)
				} else {
					if succ {
						fmt.Println("!!! Verify OpenSSLdigest Succ !!!")
					} else {
						fmt.Println("Verify PKCS1 NOT Succ")
					}
				}


			} else {
				fmt.Printf("Error load public key: %s \n", err)
			}
		} else {
			fmt.Printf("Error load private key: %s \n", err)
		}
	} else {

		// if rsa keys files not exists
		if err := GeneratePairKeys(PATH, "one"); err != nil {
			fmt.Printf("Error generate pair keys: %s \n", err)
		}
	}
}
