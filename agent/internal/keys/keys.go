// Package keys validates the global authorized_keys list served by SSH Buddy.
//
// Validation is structural, not textual: every blob is parsed by golang.org/x/crypto/ssh, so a line that merely
// looks like a key but is malformed (wrong lengths, points not on the curve, trailing bytes) is rejected.
package keys

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// MaxBytes caps the size of a key list the agent will accept.
	MaxBytes = 1 << 20
	// MinRSABits matches the server's minimum.
	MinRSABits = 2048
)

// allowed lists the only algorithms accepted. It deliberately excludes DSA, certificates
// ("*-cert-v01@openssh.com") and anything else sshd could interpret differently.
var allowed = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// ParseList validates a whole key list. It returns the number of keys, or the first problem found.
// An empty list is valid (it means "no keys are approved"). Non-empty lists must end with a newline.
func ParseList(data []byte) (int, error) {
	if len(data) > MaxBytes {
		return 0, fmt.Errorf("key list is larger than %d bytes", MaxBytes)
	}
	if len(data) == 0 {
		return 0, nil
	}
	if data[len(data)-1] != '\n' {
		return 0, errors.New("key list does not end with a newline (truncated?)")
	}

	lines := strings.Split(string(data[:len(data)-1]), "\n")
	for i, line := range lines {
		if err := ParseLine(line); err != nil {
			return 0, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return len(lines), nil
}

// ParseLine validates one line of the exact form "<algorithm> <base64 blob>[ <comment>]".
func ParseLine(line string) error {
	if line == "" {
		return errors.New("blank line")
	}
	for i := 0; i < len(line); i++ {
		if c := line[i]; c < 0x20 || c > 0x7e {
			return errors.New("contains a control or non-ASCII character")
		}
	}

	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 {
		return errors.New("expected '<algorithm> <key> [comment]'")
	}
	algo, b64 := fields[0], fields[1]
	if !allowed[algo] {
		return fmt.Errorf("unsupported key type or options present (%q)", clip(algo))
	}
	if len(fields) == 3 && (fields[2] == "" || strings.Contains(fields[2], " ")) {
		return errors.New("comment must be a single printable word")
	}

	blob, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return errors.New("key data is not valid base64")
	}
	if base64.StdEncoding.EncodeToString(blob) != b64 {
		return errors.New("key data is not canonical base64")
	}

	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return fmt.Errorf("malformed key: %v", err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return errors.New("certificates are not accepted")
	}
	if pub.Type() != algo {
		return fmt.Errorf("declared type %q does not match the key (%q)", algo, pub.Type())
	}
	if string(pub.Marshal()) != string(blob) {
		return errors.New("key data has trailing bytes")
	}
	if ck, ok := pub.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < MinRSABits {
			return fmt.Errorf("RSA key is shorter than %d bits", MinRSABits)
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
