// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"gotls/crypto"
)

var rsaSize int

// keyCmd represents the key command
var keyCmd = &cobra.Command {
	Use: "key hostname.fqdn",
	Short: "Generate a RSA private key",
	Long: `Generate a RSA private key in the current directory for the given hostname.`,
	Args: cobra.ExactArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		keyFileName := fmt.Sprintf("%s.pem", args[0])

		if _, err := crypto.GenerateKey(keyFileName, rsaSize); err != nil {
			log.Fatalf("Error generating private key: %s", err)
		} else {
			fmt.Printf("Wrote private key to %s\n", keyFileName)
		}
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA key size to use")
}
