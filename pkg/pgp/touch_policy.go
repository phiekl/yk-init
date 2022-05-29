/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package pgp

import (
	"github.com/phiekl/yk-init/pkg/sc"
)

func TouchPolicySetCachedFix(s sc.SC) (err error) {
	if err = s.TouchPolicyAUTSetCachedFixed(); err != nil {
		return
	}
	if err = s.TouchPolicyDECSetCachedFixed(); err != nil {
		return
	}
	if err = s.TouchPolicySIGSetCachedFixed(); err != nil {
		return
	}
	return
}
