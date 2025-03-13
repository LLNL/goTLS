// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var confFile string
var verbose bool

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "gotls",
	Short: "gotls is a TLS certificate issuance and management tool",
	Long: `gotls can generate keys, CSRs, and obtain a certificate
from an Active Directory Certificate Services endpoint.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

// this init() must be called before other command's init functions in order for the GenerateRevalidateViperKeyFn
// workaround to take effect
func init() {
	cobra.OnInitialize(GenerateRevalidateViperKeyFn())

	RootCmd.PersistentFlags().StringVar(&confFile, "config", "",
		"config file (default is ./.gotls.yaml or $HOME/.gotls.yaml)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enables verbose output")

	RootCmd.CompletionOptions.HiddenDefaultCmd = true

	initKey()
	initCsr()
	initCert()
}

// GenerateRevalidateViperKeyFn is used to read flags into nested config structure (workaround spf13/viper issue #368)
// from https://github.com/spf13/viper/pull/487#issuecomment-685422963
func GenerateRevalidateViperKeyFn() func() {
	return func() { initConfig("global") }
}

// initConfig reads in config file and ENV variables if set.
func initConfig(keyOrParent string) {
	if confFile != "" {
		viper.SetConfigFile(confFile)
	} else {
		viper.AddConfigPath(".") // override config from the working directory

		home, err := homedir.Dir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".gotls") // do not set the extension; viper will try all known types
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok { // Config file was found but another error was produced
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("config file: %s\n", viper.ConfigFileUsed())
	}

	viper.Set(keyOrParent, viper.AllSettings()[keyOrParent])
}
