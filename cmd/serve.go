package cmd

import (
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/jr0d/dcoscertstrap/pkg/server"
	"github.com/spf13/cobra"
)

var initServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the CA service",
	RunE:  runServer,
}

func runServer(cmd *cobra.Command, args []string) error {
	d, err := cmd.Flags().GetString("output-dir")
	if err != nil {
		return err
	}

	if err := gen.InitStorage(d); err != nil {
		return err
	}

	server.RunServer(getString(cmd, "address"), getString(cmd, "psk"))

	return nil
}

func init() {
	rootCmd.AddCommand(initServeCmd)
	initServeCmd.Flags().String("address", ":8443", "The address to listen on")
	initServeCmd.Flags().String("psk", "", "Pre-shared Key to start the server with. Clients must "+
		"authenticate using this Key")
}
