/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/phiekl/yk-init/pkg/pgp"
	"github.com/phiekl/yk-init/pkg/sc"

	"github.com/spf13/cobra"
)

var pgpSetupCmd = &cobra.Command{
	Short:        "Fully set up card from scratch (factory reset), generate keys and output resulting PGP public key.",
	Use:          "setup",
	RunE:         pgpSetup,
	SilenceUsage: true,
}

func init() {
	pgpCmd.AddCommand(pgpSetupCmd)

	pgpSetupCmd.Flags().BoolP(
		"confirm",
		"C",
		false,
		"safety measure, card won't be set up (and factory reset) without this argument set",
	)
	pgpSetupCmd.MarkFlagRequired("confirm")

	pgpSetupCmd.Flags().StringP(
		"email",
		"e",
		"",
		"pgp public key will have this userid email",
	)
	pgpSetupCmd.MarkFlagRequired("email")

	pgpSetupCmd.Flags().Uint32P(
		"lifetime",
		"l",
		0,
		"pgp public key will expire after this many seconds (default: 1 year)",
	)

	pgpSetupCmd.Flags().StringP(
		"name",
		"n",
		"",
		"pgp public key will have this userid name (and will be set as cardholder)",
	)
	pgpSetupCmd.MarkFlagRequired("name")
}

func generateRandomNumberString(min int, max int) string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%d", rand.Intn(max-min)+min)
}

type pgpSetupParam struct {
	AdminPIN string
	Email    string
	Lifetime uint32
	Name     string
	UserPIN  string
}

func (p *pgpSetupParam) validate() error {
	if p.AdminPIN == "" {
		p.AdminPIN = generateRandomNumberString(10000000, 99999999)
	} else if len(p.AdminPIN) < 8 {
		return fmt.Errorf("Admin PIN must be at least 8 characters long")
	}
	if p.Email == "" {
		return fmt.Errorf("--email must be set")
	}
	if p.Lifetime < 1 {
		p.Lifetime = 31536000 // 1 year
	}
	if p.Name == "" {
		return fmt.Errorf("--name must be set")
	}
	if p.UserPIN == "" {
		p.UserPIN = generateRandomNumberString(100000, 999999)
	} else if len(p.UserPIN) < 6 {
		return fmt.Errorf("UserPIN must be at least 6 characters long")
	}
	return nil
}

type pgpSetupResultCard struct {
	SerialNumber string
	UserPIN      string
	AdminPIN     string
}

type pgpSetupResultPGP struct {
	Fingerprint string
	PublicKey   string
}

type pgpSetupResult struct {
	Card         *pgpSetupResultCard
	PGP          *pgpSetupResultPGP
	Certificates *pgp.AttestResult
	SSH          string
}

func pgpSetup(cmd *cobra.Command, args []string) (err error) {
	param := pgpSetupParam{}
	param.AdminPIN = os.Getenv("ADMIN_PIN")
	param.Email, err = cmd.Flags().GetString("email")
	if err != nil {
		return
	}
	param.Lifetime, err = cmd.Flags().GetUint32("lifetime")
	if err != nil {
		return
	}
	param.Name, err = cmd.Flags().GetString("name")
	if err != nil {
		return
	}
	param.UserPIN = os.Getenv("USER_PIN")
	if err = param.validate(); err != nil {
		return
	}

	s := sc.SC{
		AdminPIN: "12345678",
		UserPIN:  "123456",
	}
	if err = s.Connect(); err != nil {
		return
	}
	defer s.Close()

	if err = s.FactoryReset(); err != nil {
		return
	}
	if err = s.InitProperties(param.Name); err != nil {
		return
	}
	if err = s.SetUserPIN(param.UserPIN); err != nil {
		return
	}
	if err = s.SetAdminPIN(param.AdminPIN); err != nil {
		return
	}

	g := pgp.Generate{
		Email:    param.Email,
		Lifetime: uint32(param.Lifetime), // 1 year
		Name:     param.Name,
		SC:       s,
	}
	bundle, err := g.GenerateKeyBundle()
	if err != nil {
		return err
	}

	sshAuthorizedKey, err := pgp.MarshalSSHAuthorizedKey(bundle.AutMsg.PublicKey)
	if err != nil {
		return err
	}

	if err = pgp.TouchPolicySetCachedFix(s); err != nil {
		return err
	}

	certs, err := pgp.Attest(s)
	if err != nil {
		return err
	}

	scInfo, err := s.Info()
	if err != nil {
		return err
	}

	res := &pgpSetupResult{
		Card: &pgpSetupResultCard{
			AdminPIN:     param.AdminPIN,
			SerialNumber: scInfo["serialno"][0],
			UserPIN:      param.UserPIN,
		},
		Certificates: certs,
		PGP: &pgpSetupResultPGP{
			Fingerprint: fmt.Sprintf("%X", bundle.SigKey.Fingerprint),
			PublicKey:   bundle.Serialized.String(),
		},
		SSH: sshAuthorizedKey,
	}
	output, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", output)

	return
}
