/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "yk-init",
	SilenceUsage: true,
}

// Execute runs the argument parsing and the rest of the configured program.
func Execute() error {
	return rootCmd.Execute()
}
