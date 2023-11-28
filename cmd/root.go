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

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&confFile, "config", "", "config file (default is $HOME/.gotls.yaml)")

	RootCmd.CompletionOptions.HiddenDefaultCmd = true
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if confFile != "" {
		viper.SetConfigFile(confFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
		viper.AddConfigPath(".") // override config from the working directory
		viper.AddConfigPath(home)
		viper.SetConfigName(".gotls") // do not set the extension; viper will try all known types
	}

	viper.AutomaticEnv() // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(1)
		}
	}
}
