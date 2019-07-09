package output

import (
	"fmt"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/pavel-v-chernykh/keystore-go"
	"github.com/spf13/afero"
	"log"
	"path"
	"time"
)

// AppFs afero file system abstraction
var AppFs = afero.NewOsFs()

func writeKeyStore(ks keystore.KeyStore, path, password string) error {
	o, err := AppFs.Create(path)
	if err != nil {
		return fmt.Errorf("error creating %s : %v", path, err)
	}
	defer o.Close()

	log.Printf("Creating %s", path)
	err = keystore.Encode(o, ks, []byte(password))
	if err != nil {
		return fmt.Errorf("error encoding keystore: %v", err)
	}
	return nil
}

func writeCATrustStore(caPath, outputDir, password string) error {
	const filename = "truststore.jks"
	outputPath := path.Join(outputDir, filename)
	ks := keystore.KeyStore{}

	certBytes, err := gen.ReadCertificatePEM(caPath)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", caPath, err)
	}

	ks["root-cert"] = &keystore.TrustedCertificateEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		Certificate: keystore.Certificate{
			Type:    "X509",
			Content: certBytes,
		},
	}

	return writeKeyStore(ks, outputPath, password)
}

func entityPaths(entity string) (string, string) {
	return gen.StorePath(entity + "-key.pem"), gen.StorePath(entity + "-cert.pem")
}

func writeEntityStore(alias, entity, ksPath, password string) error {
	ks := keystore.KeyStore{}
	keyPem, certPem := entityPaths(entity)
	key, err := gen.ReadPrivateKeyBytes(keyPem)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", keyPem, err)
	}

	cert, err := gen.ReadCertificatePEM(certPem)
	if err != nil {
		return fmt.Errorf("error reading %s : %v", certPem, err)
	}

	ks[alias] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey: key,
		CertChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: cert,
			},
		},
	}

	return writeKeyStore(ks, ksPath, password)
}

func writeServerStore(entity, outputDir, password string) error {
	const filename = "serverstore.jks"
	ksPath := path.Join(outputDir, filename)
	return writeEntityStore("server", entity, ksPath, password)
}

func writeClientStore(entity, outputDir, password string) error {
	const filename = "clientstore.jks"
	ksPath := path.Join(outputDir, filename)
	return writeEntityStore("client", entity, ksPath, password)
}

// WriteArtifacts creates exhibitor TLS artifacts for DC/OS
func WriteArtifacts(path, caPath, serverEntity, clientEntity, password string) error {
	err := AppFs.MkdirAll(path, 0700)
	if err != nil {
		return fmt.Errorf("error creating %s : %v", path, err)
	}

	err = writeCATrustStore(caPath, path, password)
	if err != nil {

		return err
	}

	err = writeServerStore(serverEntity, path, password)
	if err != nil {
		return err
	}

	err = writeClientStore(clientEntity, path, password)
	if err != nil {
		return err
	}

	return nil

}
