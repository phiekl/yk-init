/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023 Philip Eklöf
 */

package pgp

import (
	"crypto"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type RevocationMessageRequest struct {
	CreationTime         time.Time
	PublicKey            *packet.PublicKey
	RevocationReason     *packet.ReasonForRevocation
	RevocationReasonText string
}

func (r *RevocationMessageRequest) GenerateRevocation() *RevocationMessage {
	msg := RevocationMessage{}

	//if r.CreationTime == nil {
	//	r.CreationTime = time.Unix(time.Now().Unix(), 0).UTC()
	//}

	if r.RevocationReason == nil {
		r.RevocationReason = new(packet.ReasonForRevocation)
		*r.RevocationReason = packet.NoReason
	}

	msg.PublicKey = r.PublicKey
	msg.Sig = &packet.Signature{
		Version:              r.PublicKey.Version,
		CreationTime:         r.CreationTime,
		SigType:              packet.SigTypeKeyRevocation,
		PubKeyAlgo:           r.PublicKey.PubKeyAlgo,
		Hash:                 crypto.SHA256,
		RevocationReason:     r.RevocationReason,
		RevocationReasonText: r.RevocationReasonText,
		IssuerKeyId:          &r.PublicKey.KeyId,
	}

	return &msg
}

type RevocationMessage struct {
	PublicKey *packet.PublicKey
	Sig       *packet.Signature
}

func (m *RevocationMessage) HashRevocation() ([]byte, error) {
	digest, err := m.Sig.HashRevocation(m.PublicKey)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

func (m *RevocationMessage) Serialize(i io.Writer) error {
	err := m.Sig.Serialize(i)
	if err != nil {
		return err
	}

	return nil
}

func (m *RevocationMessage) SetRevocationSigData(sigData []byte) {
	m.Sig.SetSigData(m.PublicKey.PubKeyAlgo, sigData)
}
