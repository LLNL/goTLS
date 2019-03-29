// Copyright © 2019 Lawrence Livermore National Security
// See LICENSE file

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rsaSize int

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use: "key primary-hostname.fq.dn",
	Short: "Generate a RSA private key",
	Long: `Generate a RSA private key in the current directory for the given hostname.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		keyFileName := fmt.Sprintf("%s.pem", args[0])

		// refuse to overwrite existing key
		if _, err := os.Stat(keyFileName); err == nil {
			log.Fatalf("Error: refusing to overwrite existing %s", keyFileName)
		}

		// generate private key
		key, err := rsa.GenerateKey(rand.Reader, rsaSize)
		if err != nil {
			log.Fatalf("Error generating private key: %s", err)
		}

		// get PEM block for private key
		block := &pem.Block {
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}

		// write out PEM block to file
		keyFile, err := os.OpenFile(keyFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Error opening %s for writing: %s", keyFileName, err)
		}
		if err := pem.Encode(keyFile, block); err != nil {
			log.Fatalf("failed to write data to %s: %s", keyFileName, err)
		}
		if err := keyFile.Close(); err != nil {
			log.Fatalf("error closing %s: %s", keyFileName, err)
		}
		fmt.Printf("wrote %s\n", keyFileName)
	},
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA key size to use")
}
