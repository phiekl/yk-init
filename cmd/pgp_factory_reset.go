/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package cmd

import (
	"github.com/phiekl/yk-init/pkg/sc"

	"github.com/spf13/cobra"
)

var pgpFactoryResetCmd = &cobra.Command{
	Short:        "Perform a factory reset of the YubiKey.",
	Use:          "factory-reset",
	RunE:         pgpFactoryReset,
	SilenceUsage: true,
}

func init() {
	pgpCmd.AddCommand(pgpFactoryResetCmd)

	pgpFactoryResetCmd.Flags().BoolP(
		"confirm",
		"C",
		false,
		"factory reset won't be performed without this argument",
	)
	pgpFactoryResetCmd.MarkFlagRequired("confirm")
}

func pgpFactoryReset(cmd *cobra.Command, args []string) error {
	s := sc.SC{}
	if err := s.Connect(); err != nil {
		return err
	}
	defer s.Close()

	return s.FactoryReset()
}
