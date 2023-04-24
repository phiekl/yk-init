<!--
SPDX-License-Identifier: MIT

Copyright (c) 2022 Philip Eklöf
-->

# yk-init

This tool allows easy non-interactive initialization of a YubiKey's OpenPGP mode using sane settings and Ed25519/Curve25519 keys, ready for SSH use and [attestation](https://developers.yubico.com/PGP/Attestation.html).

To use ed25519 SSH keys with a YubiKey, its OpenPGP mode must be used. The way to do this securely is having the PGP keys generated on-device (never leaving the YubiKey), or in other words, _not_ generating the PGP keys on disk and then importing them to the YubiKey. By doing this it also allows a third party to perform attestation, which allows them to verify that your PGP (and thus SSH) private key has never seen daylight and that it never will. A nice tool for this purpose is [yk-attest-verify](https://github.com/joemiller/yk-attest-verify).

Everything that this tool does can also be performed using a series of interactive commands using `gpg --card-edit` and `ykman openpgp`. This project exists since `gpg` and `ykman` are not very easily scriptable, and also as a personal challenge, to get myself writing Go. Making this tool function has mostly been a process of "reverse engineering" gpg, lots of trial and error, and spending too much time reading RFCs and source code of various projects.

Since [x/crypto/openpgp](https://pkg.go.dev/golang.org/x/crypto/openpgp) has been [deprecated](https://github.com/golang/go/issues/44226), the [ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) fork was used instead, but as additional functionally was required in this case, it has been forked once more into [phiekl/go-crypto](https://github.com/phiekl/go-crypto).

If you'd rather want to avoid PGP/gpg altogether, just use YubiKey's PIV mode instead with ECDSA keys. A great tool for this purpose is [yubikey-agent](https://github.com/FiloSottile/yubikey-agent).

**Please note that this tool will erase any PGP keys currently stored on the YubiKey. Use at your own risk.** Also make sure to read the Gotchas at the end of this document.

# Subcommands

## pgp
```
yk-init pgp --help
```
Handles the OpenPGP mode of a YubiKey.

All communication with the YubiKey takes place via scdaemon's socket (part of gnupg), which in turn talks to pcscd.

### factory-reset
```
yk-init pgp factory-reset
```
This is a **DANGEROUS** command and does as it says; resets the PGP mode of the YubiKey to its defaults, with all keys stored on it being lost. Add argument `--confirm` to the command line to actually run it.

### setup
```
yk-init pgp setup \
  --name 'Your Name' \
  --email 'your@email' \
  --lifetime "$((10*365*24*3600))"
```

This command will initialize the YubiKey and generate the PGP keys and SSH key, and finally output a JSON object containing the PIN codes, the public keys and attestation certificates. **Make sure to save the PGP public key in the resulting JSON output as it's pretty difficult to recreate it.**

This is a **DANGEROUS** command as it will perform the same type of factory-reset as described above, hence argument `--confirm` is required here as well.

To make the YubiKey work properly with gpg afterwards, run `gpg --import` to import the public key, and then `gpg --card-status` to have gpg generate the shadow keys in `~/.gnupg/private-keys-v1.d/`, as gpg won't know that you possess the private keys otherwise. This can be repeated on any system where the YubiKey is to be used.


#### Mode of operation

1. Performs a factory reset of the PGP mode of the YubiKey.
1. Sets the GPG cardholder name according to the given --name argument.
1. Generates a random admin and user PIN (unless these are provided via the `ADMIN_PIN` and `USER_PIN` environment variables).
1. Generates ed25519/cv25519 private PGP keys (on-device, they never leave the YubiKey) and the corresponding public keys.
1. Generates a revocation certificate.
1. Generates an SSH public key based on the AUT public key.
1. Exports the attestation certificate (ATT).
1. Generates and exports attestation statements for all key slots (AUT, DEC, SIG).
1. Sets the touch policy for all the key slots (AUT, DEC, SIG) to "cached-fixed".
1. Outputs a JSON object containing:
  - The YubiKey serial number.
  - The generated admin and user PIN.
  - The fingerprint of the generated public key.
  - The serialized public key, ascii-armored.
  - The serialized revocation certificate, ascii-armored.
  - The attestation certificate (ATT).
  - The attestation statement certificates for all the key slots (AUT, DEC, SIG).
  - The SSH pubic key meant for the authorized\_keys file.

The above is basically the same procedure as running the commands below, but without any user interaction and no need to enter the PIN codes over and over again:

```
gpg --card-edit # (admin => factory-reset, name, key-attr, generate)
gpg --gen-revoke <keyid>
gpg --export-ssh-key <keyid>
ykman openpgp keys set-touch aut cached-fixed
ykman openpgp keys set-touch enc cached-fixed
ykman openpgp keys set-touch sig cached-fixed
ykman openpgp certificates export att att.pem
ykman openpgp keys attest aut aut.pem
ykman openpgp keys attest enc enc.pem
ykman openpgp keys attest sig sig.pem
ykman openpgp keys set-touch att on
```


### status
```
yk-init status
```
This command displays a very crude summary of the current PGP card via the very verbose logging. You'd probably be better off just running `gpg --card-status`.

# Gotchas

* Make sure that only a single YubiKey is currently inserted in the system.
* Only tested on Debian 11 (bullseye). Dependencies: `apt-get install pcscd scdaemon`
* Requires YubiKey firmware v5.2.3 or later since ed25519 is used for the private keys. Tested using firmware 5.2.7 and 5.4.3.
* Is `ykman` timing out with error message "No YubiKey found with the given interface(s)"? Try: `gpgconf --kill scdaemon` and `sudo systemctl restart pcscd` and then run ykman again.
