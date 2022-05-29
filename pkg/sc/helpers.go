/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package sc

import (
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
func (s *SC) AttestCertificateExport() (data []byte, err error) {
	return s.SendRecvAPDU("00ca00fc00")
}

func (s *SC) AttestStatementExport(apdu string) (data []byte, err error) {
	s.IdentifyUserPIN()

	// Select certificate to export.
	_, err = s.SendRecvAPDU(apdu)
	if err != nil {
		return nil, err
	}

	// Export certificate.
	return s.SendRecvAPDU("00ca7f2100") // reversed via ykman
}

func (s *SC) AttestStatementExportAUT() (data []byte, err error) {
	return s.AttestStatementExport("00a50004070660045c027f21") // reversed via ykman
}

func (s *SC) AttestStatementExportDEC() (data []byte, err error) {
	return s.AttestStatementExport("00a50104070660045c027f21") // reversed via ykman
}

func (s *SC) AttestStatementExportSIG() (data []byte, err error) {
	return s.AttestStatementExport("00a50204070660045c027f21") // reversed via ykman
}

func (s *SC) AttestStatementGenerateAUT() (err error) {
	s.IdentifyUserPIN()
	_, err = s.SendRecvAPDU("80fb030000") // reversed via ykman
	return err
}

func (s *SC) AttestStatementGenerateDEC() (err error) {
	s.IdentifyUserPIN()
	_, err = s.SendRecvAPDU("80fb0200000") // reversed via ykman
	return err
}

func (s *SC) AttestStatementGenerateSIG() (err error) {
	s.IdentifyUserPIN()
	_, err = s.SendRecvAPDU("80fb010000") // reversed via ykman
	return err
}

func (s *SC) FactoryReset() error {
	cmds := []string{
		"LOCK",
		"RESET",
		"SERIALNO",
		"APDU 00 A4 04 00 06 D2 76 00 01 24 01",
		"APDU 00 20 00 81 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 81 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 81 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 81 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 83 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 83 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 83 08 40 40 40 40 40 40 40 40",
		"APDU 00 20 00 83 08 40 40 40 40 40 40 40 40",
		"APDU 00 e6 00 00",
		"APDU 00 44 00 00",
		"RESET",
		"SERIALNO",
	}
	return s.SendRecvList(cmds)
}

func (s *SC) Info() (map[string][]string, error) {
	_, info, _, err := s.SendRecv("LEARN --force")
	if err != nil {
		return nil, err
	}

	if _, ok := info["serialno"]; !ok {
		return nil, fmt.Errorf("Serial number not found, smart card not connected?")
	}
	return info, nil
}

func (s *SC) InitProperties(name string) error {
	name = strings.ReplaceAll(name, " ", "+")
	cmds := []string{
		"SETATTR DISP-NAME " + name,
		"SETATTR DISP-LANG en",
		"SETATTR KEY-ATTR --force+1+22+ed25519",
		"SETATTR KEY-ATTR --force+2+18+cv25519",
		"SETATTR KEY-ATTR --force+3+22+ed25519",
	}
	if err := s.SendRecvList(cmds); err != nil {
		return err
	}
	return nil
}

func (s *SC) SetAttribute(key string, value string) error {
	value = strings.ReplaceAll(value, " ", "+")
	cmd := fmt.Sprintf("SETATTR %s %s", key, value)
	if _, _, _, err := s.SendRecv(cmd); err != nil {
		return err
	}
	return nil
}

func (s *SC) IdentifyAdminPIN() {
	cmd_start := "APDU 0020008308" // reversed via ykman
	log.Printf("> %s*Admin PIN not displayed*", cmd_start)
	pin_hex := fmt.Sprintf("%X", s.AdminPIN)
	s.SendRaw([]byte(cmd_start + pin_hex + "\n"))
	s.Recv()
}

func (s *SC) IdentifyUserPIN() {
	cmd_start := "APDU 0020008106" // reversed via ykman
	log.Printf("> %s*User PIN not displayed*", cmd_start)
	pin_hex := fmt.Sprintf("%X", s.UserPIN)
	s.SendRaw([]byte(cmd_start + pin_hex + "\n"))
	s.Recv()
}

type KeyGenerateInfo struct {
	CreationTime time.Time
	Curve        [10]byte
	KDFKEK       []byte
	Fingerprint  [20]byte
	Grip         [20]byte
	Info         map[string][]string
	PublicKey    [32]byte
}

func (s *SC) KeyGenerate(slot uint8) (*KeyGenerateInfo, error) {
	// Convert via unix time to strip any milli/nano second info.
	t := time.Unix(time.Now().Unix(), 0).UTC()

	ts := fmt.Sprintf("%d%02d%02dT%02d%02d%02d",
		t.Year(), t.Month(), t.Day(),
		t.Hour(), t.Minute(), t.Second(),
	)

	cmd := fmt.Sprintf("GENKEY --timestamp=%s --force %d", ts, slot)
	_, info, _, err := s.SendRecv(cmd)
	if err != nil {
		return nil, err
	}

	keys := []string{
		"key-created-at",
		"key-data",
		"key-fpr",
	}
	for _, k := range keys {
		if _, ok := (info[k]); !ok {
			return nil, fmt.Errorf("Metadata key not found: %s", k)
		}
	}

	res := new(KeyGenerateInfo)
	res.Info = info

	i, err := strconv.Atoi(info["key-created-at"][0])
	if err != nil {
		return nil, fmt.Errorf("Invalid key-created-at: %s\n", err)
	}
	res.CreationTime = time.Unix(int64(i), 0)

	if len(info["key-fpr"][0]) != 40 {
		return nil, fmt.Errorf("Unexpected key-fpr length: %d", len(info["key-fpr"][0]))
	}
	fp, err := hex.DecodeString(info["key-fpr"][0])
	if err != nil {
		return nil, err
	}
	copy(res.Fingerprint[:], fp)

	for _, str := range info["key-data"] {
		// replace with regex maybe
		if strings.HasPrefix(str, "curve ") {
			tokens := strings.SplitN(str, " ", 2)
			if len(tokens) != 2 {
				return nil, fmt.Errorf("Unexpected key-data curve: %s", str)
			}
			//if len(tokens[1]) != 20 {
			//	return nil, fmt.Errorf("Unexpected key-data curve length: %d", len(tokens[1]))
			//}
			curve, err := hex.DecodeString(tokens[1])
			if err != nil {
				return nil, err
			}
			copy(res.Curve[:], curve)
		} else if strings.HasPrefix(str, "kdf/kek ") {
			// https://github.com/gpg/gnupg/blob/b90c55fa66db254da98958de10e1287c39a4322a/scd/app-openpgp.c#L1516
			tokens := strings.SplitN(str, " ", 2)
			if len(tokens) != 2 {
				return nil, fmt.Errorf("Unexpected key-data kdf/kek: %s", str)
			}
			kdfkek, err := hex.DecodeString(tokens[1])
			if err != nil {
				return nil, err
			}
			copy(res.KDFKEK[:], kdfkek)
		} else if strings.HasPrefix(str, "q ") {
			tokens := strings.SplitN(str, " ", 2)
			if len(tokens) != 2 {
				return nil, fmt.Errorf("Unexpected key-data q: %s", str)
			}
			if len(tokens[1]) != 66 {
				return nil, fmt.Errorf("Unexpected key-data q length: %d", len(tokens[1]))
			}
			if tokens[1][0:2] != "40" { // prefixing @ char
				return nil, fmt.Errorf("Unexpected key-data q prefix: %s", tokens[1])
			}
			pk, err := hex.DecodeString(tokens[1][2:66])
			if err != nil {
				return nil, err
			}
			copy(res.PublicKey[:], pk)
		}
		//else {
		//	return nil, fmt.Errorf("Unexpected key data item: %s", str)
		//}
	}

	learn, err := s.Info()
	if err != nil {
		return nil, err
	}
	if _, ok := (learn["keypairinfo"]); !ok {
		return nil, fmt.Errorf("LEARN did not contain key: keypairinfo")
	}

	rgx := regexp.MustCompile(`^([0-9A-Fa-f]{40}) OPENPGP\.([0-9]+) [a-z]`)

	for _, str := range learn["keypairinfo"] {
		match := rgx.FindSubmatch([]byte(str))
		if len(match) == 0 {
			return nil, fmt.Errorf("Unexpected keypairinfo: %s", str)
		}
		if string(match[2]) == strconv.Itoa(int(slot)) {
			grip, err := hex.DecodeString(string(match[1]))
			if err != nil {
				return nil, err
			}
			copy(res.Grip[:], grip)

			return res, nil
		}
	}

	return nil, fmt.Errorf("Could not find keypairinfo matching slot %d", slot)
}

func (s *SC) PublicKeySign(digest []byte, grip []byte) ([]byte, error) {
	var cmd string

	digestHexPrefix := "3031300D060960864801650304020105000420"
	digestHex := strings.ToUpper(hex.EncodeToString(digest))
	cmd = fmt.Sprintf("SETDATA %s%s", digestHexPrefix, digestHex)
	_, _, _, err := s.SendRecv(cmd)
	if err != nil {
		return nil, err
	}

	gripHex := strings.ToUpper(hex.EncodeToString(grip))
	cmd = fmt.Sprintf("PKSIGN --hash=sha256 %s", gripHex)
	_, _, data, err := s.SendRecv(cmd)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (s *SC) SetUserPIN(newPIN string) (err error) {
	s.UserNewPIN = newPIN
	_, _, _, err = s.SendRecv("PASSWD 1")
	if err != nil {
		return
	}
	s.UserPIN = newPIN
	s.UserNewPIN = ""
	return
}

func (s *SC) SetAdminPIN(newPIN string) (err error) {
	s.AdminNewPIN = newPIN
	_, _, _, err = s.SendRecv("PASSWD 3")
	if err != nil {
		return
	}
	s.AdminPIN = newPIN
	s.AdminNewPIN = ""
	return
}

func (s *SC) TouchPolicyATTSetOff() (err error) {
	s.IdentifyAdminPIN()
	_, _, _, err = s.SendRecv("APDU 00da00d9020020") // reversed via ykman
	return err
}

func (s *SC) TouchPolicyATTSetOn() (err error) {
	s.IdentifyAdminPIN()
	_, _, _, err = s.SendRecv("APDU 00da00d9020120") // reversed via ykman
	return err
}

func (s *SC) TouchPolicyAUTSetCachedFixed() (err error) {
	s.IdentifyAdminPIN()
	_, _, _, err = s.SendRecv("APDU 00da00d6020420") // reversed via ykman
	return err
}

func (s *SC) TouchPolicyDECSetCachedFixed() (err error) {
	s.IdentifyAdminPIN()
	_, _, _, err = s.SendRecv("APDU 00da00d7020420") // reversed via ykman
	return err
}

func (s *SC) TouchPolicySIGSetCachedFixed() (err error) {
	s.IdentifyAdminPIN()
	_, _, _, err = s.SendRecv("APDU 00da00d8020420") // reversed via ykman
	return err
}
