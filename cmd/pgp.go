/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package cmd

import (
	"github.com/spf13/cobra"
)

var pgpCmd = &cobra.Command{
	Short:        "Manage OpenPGP.",
	Use:          "pgp",
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(pgpCmd)
}
