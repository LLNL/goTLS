// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var email string

// csrCmd represents the csr command
var csrCmd = &cobra.Command{
	Use: "csr primary-hostname.fq.dn [additional-hostname(s)]",
	Short: "Generate a Certificate Signing Request",
	Long: `Generate a Certificate Signing Request given a number of hostname(s).
If a private key matching the given primary hostname exists in the current
directory it will be used, otherwise a new key will be created.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("not implemented")
	},
}

func init() {
	rootCmd.AddCommand(csrCmd)

	csrCmd.Flags().StringVarP(&email, "email", "e", "", "Email address to submit")
}
