package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/spf13/cobra"
	"log"
)

// initClientCmd represents the initClient command
var initClientCmd = &cobra.Command{
	Use:   "init-client",
	Short: "Initializes a client private key",
	RunE:  initializeClient,
}

func init() {
	rootCmd.AddCommand(initClientCmd)
}

func initializeClient(cmd *cobra.Command, args []string) error {
	var keyFile = "client-key.pem"

	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}

	log.Printf("Initializing new client key at %s\n", d)
	if err := gen.InitStorage(d); err != nil {
		return err
	}

	pKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}

	if err := gen.WritePrivateKey(gen.StorePath(keyFile), pKey); err != nil {
		return err
	}

	return nil
}
