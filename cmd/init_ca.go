package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/cobra"
	"log"
)

// initCACmd represents the initCA command
var initCACmd = &cobra.Command{
	Use:   "init-ca",
	Short: "Initialize a new certificate authority",
	RunE:  initializeCA,
}

func initializeCA(cmd *cobra.Command, args []string) error {
	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}
	log.Printf("Initilizing new CA at %s\n", d)
	if err := gen.InitStorage(d); err != nil {
		return err
	}

	log.Printf("Generating private key\n")
	pKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}

	config := gen.MakeCertificateConfig(
		getString(cmd, "common-name"),
		getString(cmd, "country"),
		getString(cmd, "state"),
		getString(cmd, "locality"),
		getString(cmd, "organization"),
		getSlice(cmd, "sans"),
		getSlice(cmd, "email-addresses"),
		true,
	)

	cert, err := gen.GenerateCertificate(config, nil, pKey)
	if err != nil {
		return err
	}

	if err := gen.WritePrivateKey(gen.StorePath(gen.RootKeyFile), pKey); err != nil {
		return err
	}

	if err := gen.WriteCertificate(gen.StorePath(gen.RootCAFile), cert); err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(initCACmd)
	initCACmd.Flags().String("common-name", "ROOT", "Root certificate common name")
	initCACmd.Flags().String("country", "US", "Country name")
	initCACmd.Flags().String("state", "CA", "State or Provence")
	initCACmd.Flags().String("locality", "San Francisco", "Locality")
	initCACmd.Flags().String("organization", "Mesosphere Inc.", "organization")
	initCACmd.Flags().StringSlice("email-addresses", []string{"security@mesosphere.com"},
		"A list of administrative email addresses")
	initCACmd.Flags().StringSlice("sans", []string{}, "Subject Alternative Names")
}
