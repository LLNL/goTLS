// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package cmd

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/llnl/gotls/crypto"
)

var keyFilename string
var rsaSize int

// keyCmd represents the key command
var keyCmd = &cobra.Command{
	Use:   "key [Flags] hostname.fq.dn",
	Short: "Generate RSA private key",
	Long: `Generate RSA private key and write to a file.
The filename can be provided either to the --output parameter or will be
constructed from the first argument to this command, appended with .key,
and written to the current directory (hostname.fq.dn.key).`,
	Args:                  cobra.MaximumNArgs(1),
	DisableFlagsInUseLine: true,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 1 {
			if outputFilename != "" {
				slog.Error("Output filename must be specified in either --output parameter or as the first argument to the key command; not both.")
				os.Exit(1)
			} else {
				outputFilename = fmt.Sprintf("%s.key", args[0])
			}
		} else if len(args) == 0 {
			if outputFilename == "" {
				slog.Error("Output filename must be specified in either --output parameter or as the first argument to the key command.")
				os.Exit(1)
			}
		}

		if _, err := os.Stat(outputFilename); err == nil { // key exists
			LoadKey(outputFilename)
		} else { // key does not exist, create one
			CreateKey(outputFilename)
		}
	},
}

func LoadKey(filename string) (key any) {
	slog.Debug("loading existing private key", "filename", outputFilename)

	keyRequest := &crypto.KeyRequest{
		Filename: filename,
	}

	// load key
	key, err := crypto.GetKey(keyRequest)
	if err != nil {
		slog.Error("could not load key", "filename", filename, "error", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("private key found",
		"filename", keyRequest.Filename,
		"type", keyRequest.Type.String(),
		"container", keyRequest.Container.String(),
	)

	return key
}

func CreateKey(filename string) (key any) {
	// request RSA key in PKCS#1 container
	//TODO: allow other key and container types
	keyRequest := &crypto.KeyRequest{
		Filename:  filename,
		Type:      x509.RSA,
		Container: crypto.PKCS1,
		RsaSize:   rsaSize,
	}

	// generate key
	key, err := crypto.GenerateKey(keyRequest)
	if err != nil {
		slog.Error("could not generate private key", "filename", filename, "error", slog.Any("error", err))
		os.Exit(1)
	}

	// write key to file
	if err = crypto.WriteKey(key, keyRequest); err != nil {
		slog.Error("could not write private key", "error", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("wrote private key",
		"filename", keyRequest.Filename,
		"type", keyRequest.Type.String(),
		"container", keyRequest.Container.String(),
		"rsa-size", rsaSize,
	)

	return key
}

func initKey() {
	keyCmd.Flags().IntVarP(&rsaSize, "rsa-size", "", 2048, "RSA key size to use")
	keyCmd.Flags().StringVarP(&outputFilename, "output", "o", "", "Filename for writing private key (default is hostname.fq.dn.key)")

	RootCmd.AddCommand(keyCmd)
}
