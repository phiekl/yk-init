/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Philip Eklöf
 */

package sc

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

type SC struct {
	AdminPIN    string
	AdminNewPIN string
	UserPIN     string
	UserNewPIN  string
	conn        net.Conn
	reader      *bufio.Reader
}

func (s *SC) Connect() error {
	cmd := exec.Command("gpg-connect-agent", "scd", "/bye")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("Failed executing command 'gpg-connect-agent scd /bye'")
	}

	cmd = exec.Command("gpgconf", "--list-dir", "socketdir")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed executing command 'gpgconf --list-dir socketdir'")
	}
	if len(out) == 0 {
		return fmt.Errorf("Empty output from command 'gpgconf --list-dir socketdir'")
	}
	if out[0] != '/' {
		return fmt.Errorf("Invalid output from command 'gpgconf --list-dir socketdir': %s", out)
	}

	path := strings.TrimSuffix(string(out), "\n") + "/S.scdaemon"
	return s.Dial(path)
}

func (s *SC) Close() {
	s.conn.Close()
}

func (s *SC) Dial(path string) error {
	c, err := net.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("Failed to dial: %v", err)
	}
	s.conn = c
	s.reader = bufio.NewReader(s.conn)
	_, _, _, err = s.Recv()
	if err != nil {
		return err
	}
	return nil
}

func (s *SC) Recv() (string, map[string][]string, []byte, error) {
	var erro error
	info := make(map[string][]string)
	data := make([]byte, 0)
	text := ""

	for {
		res, err := s.reader.ReadString('\n')
		if err != nil {
			erro = err
			break
		}

		if len(res) == 0 {
			erro = fmt.Errorf("Unexpected empty response.")
			break
		}

		// strip trailing newline
		res = res[:len(res)-1]

		tokens := strings.SplitN(res, " ", 2)

		if tokens[0] == "D" {
			log.Printf("< D %x\n", tokens[1])
		} else {
			log.Printf("< %s\n", res)
		}

		if tokens[0] == "#" {
			// Comment line issued only for debugging purposes.
			continue
		} else if tokens[0] == "ERR" {
			erro = fmt.Errorf("Detected error: %s", res)
			break
		} else if tokens[0] == "D" {
			if len(tokens) != 2 {
				erro = fmt.Errorf("Unexpected empty D response.")
				break
			}
			decoded, err := PercentUnescape(tokens[1])
			if err != nil {
				erro = fmt.Errorf("Failed percent-decoding D response: %s", err)
				break
			}
			data = append(data, decoded...)
		} else if tokens[0] == "INQUIRE" {
			if len(tokens) != 2 {
				erro = fmt.Errorf("Unexpected empty INQUIRE response.")
				break
			}
			args := strings.Split(tokens[1], " ")
			if args[0] == "NEEDPIN" {
				if len(args) == 1 {
					erro = fmt.Errorf("Unexpected undefined NEEDPIN.")
					break
				}
				if strings.HasPrefix(args[1], "||") {
					s.SendPIN(s.UserPIN)
				} else if strings.HasPrefix(args[1], "|N|") {
					if s.UserNewPIN == "" {
						erro = fmt.Errorf("Got New PIN request, but no new PIN specified.")
						break
					}
					s.SendPIN(s.UserNewPIN)
				} else if strings.HasPrefix(args[1], "|A|") {
					s.SendPIN(s.AdminPIN)
				} else if strings.HasPrefix(args[1], "|AN|") {
					if s.AdminNewPIN == "" {
						erro = fmt.Errorf("Got New PIN request, but no new PIN specified.")
						break
					}
					s.SendPIN(s.AdminNewPIN)
				}
			} else {
				// Sending "CAN" would cancel the operation, but no need to implement for now.
				erro = fmt.Errorf("Unknown INQUIRE keyword: %s", args[0])
				break
			}
		} else if tokens[0] == "OK" {
			if len(tokens) == 2 {
				text = tokens[1]
			}
			break
		} else if tokens[0] == "S" {
			if len(tokens) != 2 {
				erro = fmt.Errorf("Unexpected empty S response.")
				break
			}
			args := strings.SplitN(tokens[1], " ", 2)
			key := strings.ToLower(args[0])
			if _, ok := info[key]; !ok {
				info[key] = []string{}
			}
			if len(args) == 1 {
				info[key] = append(info[key], "")
			} else {
				info[key] = append(info[key], args[1])
			}
		} else {
			erro = fmt.Errorf("Unknown response: %s", res)
			break
		}
	}

	return text, info, data, erro
}

func (s *SC) Send(cmd string) {
	log.Printf("> %s\n", cmd)
	s.SendRaw([]byte(cmd + "\n"))
}

func (s *SC) SendPIN(pin string) {
	cmd := make([]byte, 91)
	copy(cmd[0:], "D ")
	copy(cmd[2:], pin)
	cmd[90] = '\n'

	log.Printf("> D **PIN not displayed**\n")
	s.SendRaw(cmd)
	s.Send("END")
}

func (s *SC) SendRaw(cmd []byte) {
	// XXX: err return?
	s.conn.Write([]byte(cmd))
}

// Send "raw" APDU hex strings. The last four bytes of the response data is the
// the response code. If not all data is received, more will be requested, and
// the full response is returned.
// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
func (s *SC) SendRecvAPDU(apdu string) (data []byte, err error) {
	s.Send("APDU " + apdu)

	for {
		_, _, res, err := s.Recv()
		if err != nil {
			return nil, err
		}

		if len(res) == 0 {
			break
		} else if len(res) < 2 {
			return nil, fmt.Errorf("Not enough data received for APDU response code.")
		} else if len(res) > 3 {
			data = append(data, res[:len(res)-2]...)
		}

		major := res[len(res)-2]
		minor := res[len(res)-1]

		// 0x9000 => OK
		if major == 0x90 && minor == 0x00 {
			break
		}

		if major != 0x61 {
			return nil, fmt.Errorf("Unexpected response: %X", major)
		}

		// This seems to be "continue and send me more data".
		s.Send("APDU 00c0000000") // reversed via ykman
	}

	return
}

func (s *SC) SendRecv(cmd string) (string, map[string][]string, []byte, error) {
	s.Send(cmd)
	return s.Recv()
}

func (s *SC) SendRecvList(cmds []string) error {
	for _, cmd := range cmds {
		_, _, _, err := s.SendRecv(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}
