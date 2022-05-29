/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2009 The Go Authors. All rights reserved.
 * Copyright (c) 2022 Philip Eklöf
 *
 */

/*
 * This code is based on:
 * net/url/url.go (standard library)
 *
 */

package sc

import (
	"strconv"
	"strings"
)

func ishex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}
	return false
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

type EscapeError string

func (e EscapeError) Error() string {
	return "invalid percentage escape " + strconv.Quote(string(e))
}

// PercentUnescape converts each 3-byte encoded substring of the form "%AB"
// into the hex-decoded byte 0xAB. It returns an error if any % is not followed
// by two hexadecimal digits.
func PercentUnescape(s string) (string, error) {
	// Count %, check that they're well-formed.
	n := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '%':
			n++
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				s = s[i:]
				if len(s) > 3 {
					s = s[:3]
				}
				return "", EscapeError(s)
			}
			i += 3
		default:
			i++
		}
	}

	if n == 0 {
		return s, nil
	}

	var t strings.Builder
	t.Grow(len(s) - 2*n)
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			t.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		default:
			t.WriteByte(s[i])
		}
	}
	return t.String(), nil
}
