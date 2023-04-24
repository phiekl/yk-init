/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023 Philip Eklöf
 */

package pgp

import (
	"bytes"

	"github.com/phiekl/yk-init/pkg/content/pgp"
	"github.com/phiekl/yk-init/pkg/sc"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

type RevocationResult struct {
	Message    *pgp.RevocationMessage
	Serialized *bytes.Buffer
}

func GenerateRevocation(SC sc.SC, primaryKey *sc.KeyGenerateInfo, primaryMsg *pgp.PrimaryMessage) (res *RevocationResult, err error) {
	buf := bytes.NewBuffer(nil)

	writer, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}

	req := pgp.RevocationMessageRequest{
		CreationTime:         primaryMsg.PublicKey.CreationTime,
		PublicKey:            primaryMsg.PublicKey,
		RevocationReasonText: "yk-init",
	}
	msg := req.GenerateRevocation()

	digest, err := msg.HashRevocation()
	if err != nil {
		return nil, err
	}

	sig, err := SC.PublicKeySign(digest, primaryKey.Grip[:])
	if err != nil {
		return nil, err
	}
	msg.SetRevocationSigData(sig)

	err = msg.Serialize(writer)
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

	res = &RevocationResult{
		Message:    msg,
		Serialized: buf,
	}

	return
}
