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

var pgpInfoCmd = &cobra.Command{
	Short:        "Show card status.",
	Use:          "status",
	RunE:         pgpInfoMain,
	SilenceUsage: true,
}

func init() {
	pgpCmd.AddCommand(pgpInfoCmd)

	pgpInfoCmd.Flags().BoolP(
		"json",
		"J",
		false,
		"use JSON output formatting",
	)
}

func pgpInfoMain(cmd *cobra.Command, args []string) error {
	outputJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return err
	}
	_ = outputJSON

	s := sc.SC{}
	if err := s.Connect(); err != nil {
		return err
	}
	defer s.Close()

	_, err = s.Info()
	if err != nil {
		return err
	}

	return nil
}
