// SPDX-License-Identifier: CC0-1.0
//
// Copyright (c) 2022 Philip Eklöf

module github.com/phiekl/yk-init

go 1.17

replace github.com/ProtonMail/go-crypto => github.com/phiekl/go-crypto v0.0.0-20220527193337-6f71a21c96ae

require (
	github.com/ProtonMail/go-crypto v0.0.0-20220113124808-70ae35bab23f
	github.com/spf13/cobra v1.3.0
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
)

require (
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.0.0-20211205182925-97ca703d548d // indirect
)
