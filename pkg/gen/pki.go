// convenience functions for generating and querying RSA key pairs

package gen

import (
	"crypto/rand"
	"crypto/rsa"
)

const keyLength = 2048

func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, keyLength)
}
