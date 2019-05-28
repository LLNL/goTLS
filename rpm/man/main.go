// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package main

import (
	"log"

	"github.com/spf13/cobra/doc"

	"github.com/llnl/gotls/cmd"
)

func main() {
	header := &doc.GenManHeader{
		Title: "gotls",
		Section: "8",
	}
	err := doc.GenManTree(cmd.RootCmd, header, "./")
	if err != nil {
		log.Fatal(err)
	}
}
