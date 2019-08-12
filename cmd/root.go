package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1"
const versionFmt = "v" + version

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "dcos-bootstrap-ca",
	Short: "Simple program used to bootstrap TLS artifacts for " +
		"secure inter-cluster communications",
	Long: `This program is part of DC/OS and not intended for use
outside of this context`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	// enable --version flag
	rootCmd.SetVersionTemplate(fmt.Sprintln(versionFmt))
	rootCmd.Version = version

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP(
		"output-dir", "d", defaultOutputDir, "Path to store program files")
}

func getString(cmd *cobra.Command, s string) string {
	v, err := cmd.Flags().GetString(s)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return v
}

func getSlice(cmd *cobra.Command, s string) []string {
	v, err := cmd.Flags().GetStringSlice(s)
	if err != nil {
		log.Fatalf("%v\n", err)
	}
	return v
}
