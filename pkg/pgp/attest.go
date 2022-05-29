/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package pgp

import (
	"encoding/pem"

	"github.com/phiekl/yk-init/pkg/sc"
)

type AttestResult struct {
	ATT string
	AUT string
	DEC string
	SIG string
}

func Attest(s sc.SC) (res *AttestResult, err error) {
	// Make sure touch is disabled for attestation.
	if err = s.TouchPolicyATTSetOff(); err != nil {
		return
	}

	// Generate attestations.
	if err = s.AttestStatementGenerateAUT(); err != nil {
		return
	}
	if err = s.AttestStatementGenerateDEC(); err != nil {
		return
	}
	if err = s.AttestStatementGenerateSIG(); err != nil {
		return
	}

	// Re-enable touch.
	if err = s.TouchPolicyATTSetOn(); err != nil {
		return
	}

	att, err := s.AttestCertificateExport()
	if err != nil {
		return
	}

	aut, err := s.AttestStatementExportAUT()
	if err != nil {
		return
	}

	dec, err := s.AttestStatementExportDEC()
	if err != nil {
		return
	}

	sig, err := s.AttestStatementExportSIG()
	if err != nil {
		return
	}

	res = &AttestResult{
		ATT: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: att})),
		AUT: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: aut})),
		DEC: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dec})),
		SIG: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sig})),
	}

	return
}
