// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/llnl/gotls/crypto"
)

var rsaSize int

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:                   "key hostname.fqdn",
	Short:                 "Generate RSA private key",
	Long:                  `Generate RSA private key in the current directory for the given hostname.`,
	Args:                  cobra.ExactArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		keyFileName := fmt.Sprintf("%s.key", args[0])

		if _, err := crypto.GetKey(keyFileName, rsaSize); err != nil {
			fmt.Printf("Error getting private key: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	RootCmd.AddCommand(keyCmd)

	keyCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA key size to use")
}
