package cmd

import (
	"github.com/jr0d/dcoscertstrap/pkg/gen"
	"github.com/jr0d/dcoscertstrap/pkg/output"
	"github.com/spf13/cobra"
	"log"
)

const historicalPassword = "not-relevant-for-security"

var outputExhibitorCmd = &cobra.Command{
	Use:   "create-exhibitor-artifacts",
	Short: "Produces TLS artifacts for DC/OS",
	Run:   outputExhibitorArtifacts,
}

func outputExhibitorArtifacts(cmd *cobra.Command, args []string) {
	d := getString(cmd, "output-dir")
	if err := gen.InitStorage(d); err != nil {
		log.Fatalf("error initializing storage : %v", err)
	}

	err := output.WriteArtifacts(
		getString(cmd, "artifacts-directory"),
		getString(cmd, "ca"),
		getString(cmd, "server-entity"),
		getString(cmd, "client-entity"),
		historicalPassword,
	)
	if err != nil {
		log.Fatalf("error writing artifacts : %v", err)
	}
}

func init() {
	rootCmd.AddCommand(outputExhibitorCmd)
	outputExhibitorCmd.Flags().String("ca", "", "Root CA needed for truststore")
	_ = rootCmd.MarkFlagRequired("ca")
	outputExhibitorCmd.Flags().String("server-entity", "server", "Server entity name")
	outputExhibitorCmd.Flags().String("client-entity", "client", "Client entity name")
	outputExhibitorCmd.Flags().String(
		"artifacts-directory", "/var/lib/dcos/exhibitor-tls-artifacts",
		"Output director for artifacts")
}
