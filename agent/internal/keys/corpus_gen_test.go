package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The corpus is shared with the .NET suite (tests/SshBuddy.Tests/KeyCorpusTests.cs), which asserts that the
// server's PublicKeyParser reaches the same verdict. The agent rejects an ENTIRE key list when one line is
// rejected, so a key the server accepts but the agent rejects would stop revocations reaching the whole fleet.
//
//	go test ./internal/keys -run TestCorpus            checks the committed corpus against the agent
//	UPDATE_CORPUS=1 go test ./internal/keys -run TestCorpusRegenerate   rewrites ../../../testdata/key-corpus.txt
//
// Lines are "<accept|reject>|<name>|<algorithm> <base64>"; the verdict is always computed by the agent's own parser.

const corpusPath = "../../../testdata/key-corpus.txt"

func mp(b []byte) []byte { // SSH string: uint32 length + bytes
	out := []byte{byte(len(b) >> 24), byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(out, b...)
}

func str(s string) []byte { return mp([]byte(s)) }

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func b64(blob []byte) string { return base64.StdEncoding.EncodeToString(blob) }

func rsaBlob(e, n []byte) []byte { return join(str("ssh-rsa"), mp(e), mp(n)) }

func corpusCases(t *testing.T) []struct{ name, line string } {
	var cases []struct{ name, line string }
	add := func(name, algo string, blob []byte) {
		cases = append(cases, struct{ name, line string }{name, algo + " " + b64(blob)})
	}
	pubLine := func(name string, pub any) {
		k, err := ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct{ name, line string }{name, k.Type() + " " + b64(k.Marshal())})
	}

	// ---- genuine keys
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubLine("real ed25519", edPub)
	for _, bits := range []int{2048, 3072, 4096} {
		k, _ := rsa.GenerateKey(rand.Reader, bits)
		pubLine(fmt.Sprintf("real rsa %d", bits), &k.PublicKey)
	}
	short, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubLine("rsa 1024 (too short)", &short.PublicKey)
	for name, c := range map[string]elliptic.Curve{"p256": elliptic.P256(), "p384": elliptic.P384(), "p521": elliptic.P521()} {
		k, _ := ecdsa.GenerateKey(c, rand.Reader)
		pubLine("real ecdsa "+name, &k.PublicKey)
	}
	add("real sk-ed25519", "sk-ssh-ed25519@openssh.com", join(str("sk-ssh-ed25519@openssh.com"), mp(edPub), str("ssh:")))

	// ---- ECDSA points that look right (length, 0x04 prefix) but are not on the curve
	for _, c := range []struct {
		name, algo, curve string
		size              int
	}{{"p256", "ecdsa-sha2-nistp256", "nistp256", 32}, {"p384", "ecdsa-sha2-nistp384", "nistp384", 48}, {"p521", "ecdsa-sha2-nistp521", "nistp521", 66}} {
		junk := make([]byte, 2*c.size)
		rand.Read(junk)
		point := append([]byte{4}, junk...)
		add("ecdsa "+c.name+" point not on curve", c.algo, join(str(c.algo), str(c.curve), mp(point)))
		zero := append([]byte{4}, make([]byte, 2*c.size)...)
		add("ecdsa "+c.name+" point at (0,0)", c.algo, join(str(c.algo), str(c.curve), mp(zero)))
		add("ecdsa "+c.name+" compressed point", c.algo, join(str(c.algo), str(c.curve), mp(append([]byte{2}, junk[:c.size]...))))
		add("ecdsa "+c.name+" wrong curve name", c.algo, join(str(c.algo), str("nistp256"), mp(point)))
	}
	{
		junk := make([]byte, 64)
		rand.Read(junk)
		add("sk-ecdsa point not on curve", "sk-ecdsa-sha2-nistp256@openssh.com",
			join(str("sk-ecdsa-sha2-nistp256@openssh.com"), str("nistp256"), mp(append([]byte{4}, junk...)), str("ssh:")))
	}

	// ---- RSA with unusual exponents / encodings. Modulus: a real 2048-bit key's n.
	good, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := good.N
	nb := n.Bytes() // high bit set, so a minimal mpint needs a leading 0x00
	nMin := append([]byte{0}, nb...)
	e65537 := []byte{1, 0, 1}
	add("rsa e=65537 minimal", "ssh-rsa", rsaBlob(e65537, nMin))
	add("rsa e=3", "ssh-rsa", rsaBlob([]byte{3}, nMin))
	add("rsa e=2 (even)", "ssh-rsa", rsaBlob([]byte{2}, nMin))
	add("rsa e=1", "ssh-rsa", rsaBlob([]byte{1}, nMin))
	add("rsa e=0", "ssh-rsa", rsaBlob([]byte{}, nMin))
	add("rsa e=65538 (even)", "ssh-rsa", rsaBlob([]byte{1, 0, 2}, nMin))
	add("rsa e=2^24+1 (too large)", "ssh-rsa", rsaBlob([]byte{1, 0, 0, 1}, nMin))
	add("rsa e=2^23+1", "ssh-rsa", rsaBlob([]byte{0, 0x80, 0, 1}, nMin))
	add("rsa e with redundant leading zero", "ssh-rsa", rsaBlob([]byte{0, 1, 0, 1}, nMin))
	add("rsa n with redundant leading zero", "ssh-rsa", rsaBlob(e65537, append([]byte{0}, nMin...)))
	add("rsa n negative (no leading zero)", "ssh-rsa", rsaBlob(e65537, nb))
	add("rsa n even", "ssh-rsa", rsaBlob(e65537, append(append([]byte{0}, nb[:len(nb)-1]...), nb[len(nb)-1]&^1)))
	add("rsa n zero", "ssh-rsa", rsaBlob(e65537, []byte{}))
	add("rsa n = 2^2047 (power of two)", "ssh-rsa", rsaBlob(e65537, mpintRaw(new(big.Int).Lsh(big.NewInt(1), 2047))))
	add("rsa trailing bytes", "ssh-rsa", append(rsaBlob(e65537, nMin), 0xde, 0xad))
	add("rsa n 16385 bits", "ssh-rsa", rsaBlob(e65537, mpintRaw(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 16384), big.NewInt(1)))))
	add("rsa n 16384 bits", "ssh-rsa", rsaBlob(e65537, mpintRaw(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 16383), big.NewInt(1)))))

	// ---- ed25519 / sk
	add("ed25519 31 bytes", "ssh-ed25519", join(str("ssh-ed25519"), mp(edPub[:31])))
	add("ed25519 33 bytes", "ssh-ed25519", join(str("ssh-ed25519"), mp(append(append([]byte{}, edPub...), 0))))
	add("ed25519 trailing bytes", "ssh-ed25519", append(join(str("ssh-ed25519"), mp(edPub)), 1))
	add("ed25519 name mismatch", "ssh-ed25519", join(str("ssh-rsa"), mp(edPub)))
	add("ed25519 truncated", "ssh-ed25519", join(str("ssh-ed25519"), mp(edPub))[:20])
	add("sk-ed25519 empty application", "sk-ssh-ed25519@openssh.com", join(str("sk-ssh-ed25519@openssh.com"), mp(edPub), str("")))
	add("sk-ed25519 missing application", "sk-ssh-ed25519@openssh.com", join(str("sk-ssh-ed25519@openssh.com"), mp(edPub)))
	add("sk-ed25519 31-byte key", "sk-ssh-ed25519@openssh.com", join(str("sk-ssh-ed25519@openssh.com"), mp(edPub[:31]), str("ssh:")))

	// ---- not-key lines
	cases = append(cases,
		struct{ name, line string }{"dsa", "ssh-dss " + b64(join(str("ssh-dss"), mp([]byte{1}), mp([]byte{1}), mp([]byte{1}), mp([]byte{1})))},
		struct{ name, line string }{"unknown algorithm", "ssh-foo " + b64(join(str("ssh-foo"), mp(edPub)))},
		struct{ name, line string }{"cert algorithm with plain blob", "ssh-ed25519-cert-v01@openssh.com " + b64(join(str("ssh-ed25519"), mp(edPub)))},
		struct{ name, line string }{"not base64", "ssh-ed25519 !!!!"},
		struct{ name, line string }{"empty base64", "ssh-ed25519 "},
		struct{ name, line string }{"private key marker", "-----BEGIN OPENSSH PRIVATE KEY-----"},
	)
	return cases
}

// mpintRaw is the minimal two's-complement big-endian encoding: a leading 0x00 only when the high bit is set.
func mpintRaw(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

func verdict(line string) string {
	if ParseLine(line) == nil {
		return "accept"
	}
	return "reject"
}

func TestCorpusRegenerate(t *testing.T) {
	if os.Getenv("UPDATE_CORPUS") == "" {
		t.Skip("set UPDATE_CORPUS=1 to rewrite the shared corpus")
	}
	cases := corpusCases(t)
	sort.SliceStable(cases, func(i, j int) bool { return cases[i].name < cases[j].name })
	var sb strings.Builder
	sb.WriteString("# Shared key corpus. Verdicts come from the Go agent's parser (agent/internal/keys). Regenerate with:\n")
	sb.WriteString("#   cd agent && UPDATE_CORPUS=1 go test ./internal/keys -run TestCorpusRegenerate\n")
	sb.WriteString("# Format: <accept|reject>|<name>|<algorithm> <base64>\n")
	for _, c := range cases {
		fmt.Fprintf(&sb, "%s|%s|%s\n", verdict(c.line), c.name, c.line)
	}
	path := filepath.Clean(corpusPath)
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases to %s", len(cases), path)
}

// TestCorpus keeps the committed corpus honest: the agent must still give every line the recorded verdict.
func TestCorpus(t *testing.T) {
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("corpus missing (run UPDATE_CORPUS=1 go test -run TestCorpusRegenerate): %v", err)
	}
	n := 0
	for _, raw := range strings.Split(string(data), "\n") {
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, "|", 3)
		if len(parts) != 3 {
			t.Fatalf("bad corpus line %q", raw)
		}
		n++
		if got := verdict(parts[2]); got != parts[0] {
			t.Errorf("%s: agent now says %s, corpus says %s", parts[1], got, parts[0])
		}
	}
	if n < 40 {
		t.Errorf("corpus suspiciously small: %d cases", n)
	}
}
