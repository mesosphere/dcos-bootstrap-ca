package gen

import (
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/afero"
	"testing"
)

const testStorePath = "/test/.pki"

func TestWritePrivateKey(t *testing.T) {
	gen.AppFs = afero.NewMemMapFs()
	_ = gen.InitStorage(testStorePath)
	pKey, _ := gen.GenerateRSAPrivateKey()
	e := gen.WritePrivateKey(gen.StorePath("private.key"), pKey)
	if e != nil {
		t.Fatalf("Failed to write private key: %v", e)
	}
}
