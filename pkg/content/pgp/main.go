/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package pgp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"io"
	"math/big"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/algorithm"
	"github.com/ProtonMail/go-crypto/openpgp/ecc"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type PrimaryMessageRequest struct {
	Comment      string
	CreationTime time.Time
	Email        string
	Lifetime     uint32
	Name         string
	PublicKey    []byte
}

func (r *PrimaryMessageRequest) GeneratePrimaryKey() (*PrimaryMessage, error) {
	msg := PrimaryMessage{}

	pk := ed25519.PublicKey(r.PublicKey)
	msg.PublicKey = packet.NewEdDSAPublicKey(r.CreationTime, &pk)

	msg.UserId = packet.NewUserId(r.Name, r.Comment, r.Email)

	msg.UserIdSig = &packet.Signature{
		CreationTime:         r.CreationTime,
		FlagCertify:          true,
		FlagSign:             true,
		FlagsValid:           true,
		Hash:                 crypto.SHA256,
		IssuerKeyId:          &msg.PublicKey.KeyId,
		KeyLifetimeSecs:      &r.Lifetime,
		MDC:                  true,
		PreferredCompression: []uint8{2, 3, 1},
		PreferredHash:        []uint8{10, 9, 8, 11, 2},
		PreferredSymmetric:   []uint8{9, 8, 7, 2},
		PubKeyAlgo:           msg.PublicKey.PubKeyAlgo,
		SigLifetimeSecs:      &r.Lifetime,
		SigType:              packet.SigTypePositiveCert,
	}

	return &msg, nil
}

type PrimaryMessage struct {
	PublicKey *packet.PublicKey
	UserId    *packet.UserId
	UserIdSig *packet.Signature
}

func (m *PrimaryMessage) HashUserIdPub() ([]byte, error) {
	digest, err := m.UserIdSig.HashUserId(m.UserId.Id, m.PublicKey)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

func (m *PrimaryMessage) SetUserIdSigData(sigData []byte) {
	m.UserIdSig.SetSigData(m.PublicKey.PubKeyAlgo, sigData)
}

func (m *PrimaryMessage) Serialize(i io.Writer) error {
	err := m.PublicKey.Serialize(i)
	if err != nil {
		return err
	}
	err = m.UserId.Serialize(i)
	if err != nil {
		return err
	}
	err = m.UserIdSig.Serialize(i)
	if err != nil {
		return err
	}

	return nil
}

type SubkeyMessageRequest struct {
	CreationTime              time.Time
	Lifetime                  uint32
	PublicKey                 []byte
	IssuerPublicKey           *packet.PublicKey
	FlagAuthenticate          bool
	FlagEncryptCommunications bool
	FlagEncryptStorage        bool
}

func (r *SubkeyMessageRequest) GenerateSubkey(msg SubkeyMessage) (*SubkeyMessage, error) {
	msg.Sig = &packet.Signature{
		CreationTime:              r.CreationTime,
		FlagAuthenticate:          r.FlagAuthenticate,
		FlagEncryptCommunications: r.FlagEncryptCommunications,
		FlagEncryptStorage:        r.FlagEncryptStorage,
		FlagsValid:                true,
		Hash:                      crypto.SHA256,
		IssuerKeyId:               &r.IssuerPublicKey.KeyId,
		KeyLifetimeSecs:           &r.Lifetime,
		PubKeyAlgo:                r.IssuerPublicKey.PubKeyAlgo,
		SigLifetimeSecs:           &r.Lifetime,
		SigType:                   packet.SigTypeSubkeyBinding,
	}

	msg.PublicKey.IsSubkey = true
	msg.IssuerPublicKey = r.IssuerPublicKey

	return &msg, nil
}

func (r *SubkeyMessageRequest) GenerateSubkeyEdDSA() (*SubkeyMessage, error) {
	pk := ed25519.PublicKey(r.PublicKey)
	msg := SubkeyMessage{
		PublicKey: packet.NewEdDSAPublicKey(r.CreationTime, &pk),
	}
	return r.GenerateSubkey(msg)
}

func (r *SubkeyMessageRequest) GenerateSubkeyECDH() (*SubkeyMessage, error) {
	pk := new(ecdh.PublicKey)

	// These are the properties used when gpg itself generates pubkeys.
	pk.CurveType = ecc.Curve25519
	pk.Curve = elliptic.P256()
	pk.KDF = ecdh.KDF{Hash: algorithm.SHA256, Cipher: algorithm.AES128}

	// https://datatracker.ietf.org/doc/html/draft-koch-eddsa-for-openpgp-00#section-3
	pkData := make([]byte, 1+len(r.PublicKey))
	pkData[0] = 0x40
	copy(pkData[1:], r.PublicKey[:])
	pk.X = new(big.Int).SetBytes(pkData[:])

	msg := SubkeyMessage{
		PublicKey: packet.NewECDHPublicKey(r.CreationTime, pk),
	}
	return r.GenerateSubkey(msg)
}

type SubkeyMessage struct {
	PublicKey       *packet.PublicKey
	IssuerPublicKey *packet.PublicKey
	Sig             *packet.Signature
}

func (m *SubkeyMessage) HashSubKeyPub() ([]byte, error) {
	digest, err := m.Sig.HashSubkey(m.PublicKey, m.IssuerPublicKey)
	if err != nil {
		return nil, err
	}
	return digest, nil
}

func (m *SubkeyMessage) SetSubKeySigData(sigData []byte) {
	m.Sig.SetSigData(m.PublicKey.PubKeyAlgo, sigData)
}

func (m *SubkeyMessage) Serialize(i io.Writer) error {
	err := m.PublicKey.Serialize(i)
	if err != nil {
		return err
	}
	err = m.Sig.Serialize(i)
	if err != nil {
		return err
	}

	return nil
}
