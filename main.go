// Copyright © 2019 Lawrence Livermore National Security, LLC
// SPDX-License-Identifier: MIT
// See top-level LICENSE file for details.

package main

import (
	"log/slog"
	"os"

	"github.com/llnl/gotls/cmd"
	"github.com/llnl/gotls/conhandler"
)

var logLevel *slog.LevelVar

// in the beginning, there was master. master begat main, which begat cmd, which ...
func main() {
	initLogger()

	if err := cmd.Execute(logLevel); err != nil {
		slog.Error("could not execute command", slog.Any("error", err))
		os.Exit(1)
	}
}

func initLogger() {
	// instantiate logger without timestamps and without INFO label
	logLevel = new(slog.LevelVar)

	logger := slog.New(conhandler.NewConsoleHandler(os.Stdout, &conhandler.Options{Level: logLevel, RemoveTime: true, RemoveInfoLabel: true}))

	slog.SetDefault(logger)
}
