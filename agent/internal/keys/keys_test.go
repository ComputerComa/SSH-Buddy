package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func authorizedLine(t *testing.T, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func edLine(t *testing.T) string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return authorizedLine(t, pub)
}

func rsaLine(t *testing.T, bits int) string {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return authorizedLine(t, &k.PublicKey)
}

func ecLine(t *testing.T, c elliptic.Curve) string {
	k, _ := ecdsa.GenerateKey(c, rand.Reader)
	return authorizedLine(t, &k.PublicKey)
}

func blobOf(line string) []byte {
	b, _ := base64.StdEncoding.DecodeString(strings.Fields(line)[1])
	return b
}

func TestAcceptsRealKeysOfEveryAllowedType(t *testing.T) {
	lines := []string{
		edLine(t) + " alice@laptop",
		edLine(t),
		rsaLine(t, 2048) + " rsa_key",
		rsaLine(t, 3072),
		ecLine(t, elliptic.P256()) + " p256",
		ecLine(t, elliptic.P384()) + " p384",
		ecLine(t, elliptic.P521()) + " p521",
	}
	// a hardware-backed key: build a valid sk-ssh-ed25519 wire blob
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sk := ssh.Marshal(struct {
		Name, Key, App string
	}{"sk-ssh-ed25519@openssh.com", string(pub), "ssh:"})
	lines = append(lines, "sk-ssh-ed25519@openssh.com "+base64.StdEncoding.EncodeToString(sk)+" yubikey")

	for _, l := range lines {
		if err := ParseLine(l); err != nil {
			t.Errorf("rejected valid key %q: %v", l[:30], err)
		}
	}
	n, err := ParseList([]byte(strings.Join(lines, "\n") + "\n"))
	if err != nil || n != len(lines) {
		t.Fatalf("ParseList = %d, %v", n, err)
	}
}

func TestEmptyListIsValid(t *testing.T) {
	if n, err := ParseList(nil); err != nil || n != 0 {
		t.Fatalf("empty list: %d, %v", n, err)
	}
	if n, err := ParseList([]byte{}); err != nil || n != 0 {
		t.Fatalf("empty list: %d, %v", n, err)
	}
}

func TestRejectsMalformedAndDangerousLines(t *testing.T) {
	good := edLine(t)
	blob := blobOf(good)
	b64 := strings.Fields(good)[1]

	// a certificate signed by a throwaway CA
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = caPub
	signer, _ := ssh.NewSignerFromKey(caPriv)
	userPub, _, _ := ed25519.GenerateKey(rand.Reader)
	uk, _ := ssh.NewPublicKey(userPub)
	cert := &ssh.Certificate{Key: uk, CertType: ssh.UserCert, ValidBefore: uint64(time.Now().Add(time.Hour).Unix()), ValidPrincipals: []string{"root"}}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	certLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))

	cases := map[string]string{
		"empty":                "",
		"only algorithm":       "ssh-ed25519",
		"options prefix":       `command="/bin/evil" ` + good,
		"from option":          `from="10.0.0.1",no-pty ` + good,
		"restrict":             "restrict " + good,
		"certificate":          certLine,
		"cert type, plain key": "ssh-ed25519-cert-v01@openssh.com " + b64,
		"dsa":                  "ssh-dss " + b64,
		"unknown":              "ssh-foo " + b64,
		"bad base64":           "ssh-ed25519 !!!!",
		"non canonical b64":    "ssh-ed25519 " + strings.TrimRight(b64, "=") + "A",
		"truncated blob":       "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob[:len(blob)-5]),
		"trailing bytes":       "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(append([]byte{}, blob...), 1, 2, 3)),
		"type mismatch":        "ssh-rsa " + b64,
		"comment with space":   good + " two words",
		"trailing space":       good + " ",
		"tab separator":        strings.Replace(good, " ", "\t", 1),
		"carriage return":      good + "\r",
		"nul byte":             good + "\x00",
		"non ascii comment":    good + " héllo",
		"short rsa":            rsaLine(t, 1024),
		"private key marker":   "-----BEGIN OPENSSH PRIVATE KEY-----",
		"double key one line":  good + " " + good,
	}
	for name, line := range cases {
		if err := ParseLine(line); err == nil {
			t.Errorf("%s: accepted %q", name, clipForLog(line))
		}
	}
}

func clipForLog(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}

func TestListLevelRules(t *testing.T) {
	g := edLine(t)
	for name, data := range map[string]string{
		"no trailing newline": g,
		"blank line":          g + "\n\n",
		"crlf":                g + "\r\n",
		"one bad line":        g + "\n" + g + "x\n",
		"html":                "<html>portal</html>\n",
		"leading blank":       "\n" + g + "\n",
	} {
		if _, err := ParseList([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOversizeListIsRejected(t *testing.T) {
	line := edLine(t) + "\n"
	big := strings.Repeat(line, MaxBytes/len(line)+2)
	if _, err := ParseList([]byte(big)); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversize list: %v", err)
	}
}
