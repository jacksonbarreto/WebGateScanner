package scanner

import "os/exec"

type Scanner struct {
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Scan(host string) error {

	cmd := exec.Command("/home/stls/testssl.sh/testssl.sh", "--jsonfile-pretty", "/home/stls/results/", host)

	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
