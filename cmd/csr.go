// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var email string
var c string
var st string
var l string
var o string
var ou string

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use: "csr primary-hostname.fq.dn [additional-hostname(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given a number of hostname(s).
If a private key matching the given primary hostname exists in the current
directory it will be used, otherwise a new key will be created.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// load flag variables
		c = viper.GetString("c")
		st = viper.GetString("st")
		l = viper.GetString("l")
		o = viper.GetString("o")
		ou = viper.GetString("ou")
		email = viper.GetString("email")

		fmt.Printf("C: %s\n", c)
		fmt.Printf("ST: %s\n", st)
		fmt.Printf("L: %s\n", l)
		fmt.Printf("O: %s\n", o)
		fmt.Printf("OU: %s\n", ou)
		fmt.Printf("email: %s\n", email)
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)

	// define flags
	csrCmd.Flags().StringVarP(&email, "email", "e", "", "Email address to submit")
	csrCmd.Flags().StringVarP(&c, "c", "c", "", "Country field for CSR")
	csrCmd.Flags().StringVarP(&st, "st", "", "", "State field for CSR")
	csrCmd.Flags().StringVarP(&l, "l", "l", "", "Locality or city field for CSR")
	csrCmd.Flags().StringVarP(&o, "o", "o", "", "Organization field for CSR")
	csrCmd.Flags().StringVarP(&ou, "ou", "", "", "Organization Unit field for CSR")

	// bind flags to conf file values (appears to be case-insensitive)
	viper.BindPFlag("c", csrCmd.Flags().Lookup("c"))
	viper.BindPFlag("st", csrCmd.Flags().Lookup("st"))
	viper.BindPFlag("l", csrCmd.Flags().Lookup("l"))
	viper.BindPFlag("o", csrCmd.Flags().Lookup("o"))
	viper.BindPFlag("ou", csrCmd.Flags().Lookup("ou"))
	viper.BindPFlag("email", csrCmd.Flags().Lookup("email"))
}
