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
	Use:   "init-entity",
	Short: "Initializes an end entity private key",
	RunE:  initializeClient,
	Args:  cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(initClientCmd)
}

func initializeClient(cmd *cobra.Command, args []string) error {
	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}

	entity := args[0]
	entityFile := entity + "-key.pem"

	if err := gen.InitStorage(d); err != nil {
		return err
	}

	log.Printf("Initializing new entity key at %s\n", gen.StorePath(entityFile))

	pKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return err
	}

	if err := gen.WritePrivateKey(gen.StorePath(entityFile), pKey); err != nil {
		return err
	}

	return nil
}
