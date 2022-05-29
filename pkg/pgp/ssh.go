/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package pgp

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

func MarshalSSHAuthorizedKey(pgpPublicKey *packet.PublicKey) (string, error) {
	pk, ok := pgpPublicKey.PublicKey.(*ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("Only ed25519 public keys supported.")
	}

	sshPK, err := ssh.NewPublicKey(*pk)
	if err != nil {
		return "", err
	}

	sshAK := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPK)), "\n")

	return sshAK, nil
}
