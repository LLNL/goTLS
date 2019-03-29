// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"fmt"
	"os"

	//homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var confFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command {
	Use: "gotls",
	Short: "gotls is an automated TLS certificate issuance and management tool",
	Long: `gotls can generate keys, CSRs, and optionally obtain the certificate
with an internal Active Directory Certificate Services endpoint or the
Let's Encrypt service.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// persistent flags will be global for your application.
	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.gotls.yaml)")

	// local flags will only run when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	//if cfgFile != "" {
	//	// Use config file from the flag.
	//	viper.SetConfigFile(cfgFile)
	//} else {
	//	// Find home directory.
	//	home, err := homedir.Dir()
	//	if err != nil {
	//		fmt.Println(err)
	//		os.Exit(1)
	//	}
	//
	//	// Search config in home directory with name ".gotls" (without extension).
	//	viper.AddConfigPath(home)
	//	viper.SetConfigName(".gotls")
	//}

	viper.AutomaticEnv() // read in environment variables that match

	//// If a config file is found, read it in.
	//if err := viper.ReadInConfig(); err == nil {
	//	fmt.Println("Using config file:", viper.ConfigFileUsed())
	//}
}
