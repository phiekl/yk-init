/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package pgp

import (
	"bytes"
	"fmt"

	"github.com/phiekl/yk-init/pkg/content/pgp"
	"github.com/phiekl/yk-init/pkg/sc"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const (
	SlotSign = iota + 1
	SlotEncrypt
	SlotAuthenticate
)

type Generate struct {
	Email    string
	Lifetime uint32
	Name     string
	SC       sc.SC
}

type GenerateResult struct {
	AutKey     *sc.KeyGenerateInfo
	AutMsg     *pgp.SubkeyMessage
	EncKey     *sc.KeyGenerateInfo
	EncMsg     *pgp.SubkeyMessage
	Serialized *bytes.Buffer
	SigKey     *sc.KeyGenerateInfo
	SigMsg     *pgp.PrimaryMessage
}

func (g *Generate) GenerateKeyBundle() (res *GenerateResult, err error) {
	buf := bytes.NewBuffer(nil)

	writer, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}

	sigKey, sigMsg, err := g.GeneratePrimaryKey()
	if err != nil {
		return
	}
	err = sigMsg.Serialize(writer)
	if err != nil {
		return
	}

	encKey, encMsg, err := g.GenerateSubkey(SlotEncrypt, sigKey, sigMsg)
	if err != nil {
		return
	}
	err = encMsg.Serialize(writer)
	if err != nil {
		return
	}

	autKey, autMsg, err := g.GenerateSubkey(SlotAuthenticate, sigKey, sigMsg)
	if err != nil {
		return
	}
	err = autMsg.Serialize(writer)
	if err != nil {
		return
	}

	err = writer.Close()
	if err != nil {
		return
	}
	err = buf.WriteByte('\n')
	if err != nil {
		return
	}

	res = &GenerateResult{
		AutKey:     autKey,
		AutMsg:     autMsg,
		EncKey:     encKey,
		EncMsg:     encMsg,
		Serialized: buf,
		SigKey:     sigKey,
		SigMsg:     sigMsg,
	}

	return
}

func (g *Generate) GeneratePrimaryKey() (*sc.KeyGenerateInfo, *pgp.PrimaryMessage, error) {
	// Generate a new key on slot 1 (signing key) on the yubikey.
	key, err := g.SC.KeyGenerate(uint8(1))
	if err != nil {
		return nil, nil, err
	}

	req := pgp.PrimaryMessageRequest{
		CreationTime: key.CreationTime,
		Email:        g.Email,
		Lifetime:     g.Lifetime,
		Name:         g.Name,
		PublicKey:    key.PublicKey[:],
	}
	msg, err := req.GeneratePrimaryKey()
	if err != nil {
		return nil, nil, err
	}

	digest, err := msg.HashUserIdPub()
	if err != nil {
		return nil, nil, err
	}

	sig, err := g.SC.PublicKeySign(digest, key.Grip[:])
	if err != nil {
		return nil, nil, err
	}
	msg.SetUserIdSigData(sig)

	return key, msg, err
}

func (g *Generate) GenerateSubkey(slot uint8, primaryKey *sc.KeyGenerateInfo, primaryMsg *pgp.PrimaryMessage) (key *sc.KeyGenerateInfo, msg *pgp.SubkeyMessage, err error) {
	if (slot != SlotEncrypt) && (slot != SlotAuthenticate) {
		err = fmt.Errorf("Unexpected slot given: %d", slot)
		return
	}

	key, err = g.SC.KeyGenerate(slot)
	if err != nil {
		return
	}

	req := pgp.SubkeyMessageRequest{
		CreationTime:    key.CreationTime,
		Lifetime:        g.Lifetime,
		PublicKey:       key.PublicKey[:],
		IssuerPublicKey: primaryMsg.PublicKey,
	}

	if slot == SlotAuthenticate {
		req.FlagAuthenticate = true
		msg, err = req.GenerateSubkeyEdDSA()
		if err != nil {
			return
		}
	} else if slot == SlotEncrypt {
		req.FlagEncryptCommunications = true
		req.FlagEncryptStorage = true
		msg, err = req.GenerateSubkeyECDH()
		if err != nil {
			return
		}
	}

	digest, err := msg.HashSubKeyPub()
	if err != nil {
		return
	}
	sig, err := g.SC.PublicKeySign(digest, primaryKey.Grip[:])
	if err != nil {
		return
	}
	msg.SetSubKeySigData(sig)

	return
}
