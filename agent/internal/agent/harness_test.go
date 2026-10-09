package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeServer imitates the SSH Buddy API closely enough to exercise real HTTP/TLS behaviour.
type fakeServer struct {
	*httptest.Server
	mu sync.Mutex

	keyBody   string
	keyStatus int // 0 = behave normally
	ignoreINM bool
	alwaysNM  bool
	sleep     func()

	keyRequests            []http.Header
	enrolls                []map[string]string
	checkins               []checkin
	checkinCode            int // 0 = 204
	enrollCode             int // 0 = 201
	dropNextEnrollResponse bool
	credential             string
	checkinAccepts         string // when set, only this bearer credential is accepted
}

type checkin struct {
	Auth    string
	Payload map[string]string
}

func etagOf(body string) string { return `"` + sha256Hex([]byte(body))[:16] + `"` }

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{credential: "sbm_testcredential_0123456789abcdefghijklmnop"}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/authorized-keys", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.keyRequests = append(f.keyRequests, r.Header.Clone())
		body, status, ignore, always, sleep := f.keyBody, f.keyStatus, f.ignoreINM, f.alwaysNM, f.sleep
		f.mu.Unlock()
		if sleep != nil {
			sleep()
		}
		if status != 0 {
			if status >= 300 && status < 400 {
				w.Header().Set("Location", "http://evil.example/")
			}
			w.WriteHeader(status)
			return
		}
		et := etagOf(body)
		w.Header().Set("ETag", et)
		if always || (!ignore && r.Header.Get("If-None-Match") == et) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		io.WriteString(w, body)
	})
	mux.HandleFunc("/api/machines/enroll", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		readJSON(r, &m)
		m["_auth"] = r.Header.Get("Authorization")
		f.mu.Lock()
		f.enrolls = append(f.enrolls, m)
		code, drop := f.enrollCode, f.dropNextEnrollResponse
		f.dropNextEnrollResponse = false
		cred := f.credential
		f.mu.Unlock()
		if drop {
			if hj, ok := w.(http.Hijacker); ok {
				c, _, _ := hj.Hijack()
				c.Close() // the credential was "issued" but the response never arrives
				return
			}
		}
		if code != 0 {
			w.WriteHeader(code)
			fmt.Fprint(w, `{"detail":"refused"}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"fqdn":%q,"machineCredential":%q}`, m["fqdn"], cred)
	})
	mux.HandleFunc("/api/machines/checkin", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		readJSON(r, &m)
		f.mu.Lock()
		f.checkins = append(f.checkins, checkin{Auth: r.Header.Get("Authorization"), Payload: m})
		code := f.checkinCode
		if f.checkinAccepts != "" && r.Header.Get("Authorization") != "Bearer "+f.checkinAccepts {
			code = http.StatusUnauthorized
		} else if f.checkinAccepts != "" {
			code = 0
		}
		f.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) set(fn func(*fakeServer)) { f.mu.Lock(); defer f.mu.Unlock(); fn(f) }

func (f *fakeServer) snapshot() (keyReqs []http.Header, enrolls []map[string]string, checkins []checkin) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]http.Header(nil), f.keyRequests...), append([]map[string]string(nil), f.enrolls...), append([]checkin(nil), f.checkins...)
}

type env struct {
	t     *testing.T
	dir   string
	srv   *fakeServer
	agent *Agent
	log   *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	srv := newFakeServer(t)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	p := Paths{
		ConfigFile:      filepath.Join(dir, "etc", "agent.conf"),
		EnrollTokenFile: filepath.Join(dir, "etc", "enroll-token"),
		StateDir:        filepath.Join(dir, "var"),
		ManagedFile:     filepath.Join(dir, "ssh", "authorized_keys.d", "root-managed"),
		LockFile:        filepath.Join(dir, "agent.lock"),
		HostsFile:       filepath.Join(dir, "hosts"),
		ResolvConf:      filepath.Join(dir, "resolv.conf"),
	}
	if err := os.MkdirAll(filepath.Dir(p.EnrollTokenFile), 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(p.EnrollTokenFile, []byte("sbt_template_credential_value_0123456789\n"), 0o600))

	log := &bytes.Buffer{}
	e := &env{t: t, dir: dir, srv: srv, log: log}
	e.agent = &Agent{
		Config:   Config{BaseURL: srv.URL, Interval: DefaultInterval},
		Paths:    p,
		Owner:    Owner{UID: os.Getuid(), GID: os.Getgid()},
		Version:  "9.9.9-test",
		HTTP:     NewHTTPClient(pool),
		Hostname: func() (string, error) { return "web1.example.com", nil },
		Log:      log,
	}
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (e *env) managed() string {
	b, err := os.ReadFile(e.agent.Paths.ManagedFile)
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (e *env) inode(path string) uint64 {
	fi, err := os.Stat(path)
	must(e.t, err)
	return fi.Sys().(*syscall.Stat_t).Ino
}

func (e *env) leftovers() []string {
	var out []string
	for _, d := range []string{filepath.Dir(e.agent.Paths.ManagedFile), e.agent.Paths.StateDir} {
		ents, _ := os.ReadDir(d)
		for _, ent := range ents {
			if strings.Contains(ent.Name(), ".tmp-") {
				out = append(out, filepath.Join(d, ent.Name()))
			}
		}
	}
	return out
}

func readJSON(r *http.Request, into *map[string]string) {
	b, _ := io.ReadAll(r.Body)
	*into = map[string]string{}
	_ = json.Unmarshal(b, into)
}

var edCounter int

func newKey(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	must(t, err)
	edCounter++
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + fmt.Sprintf(" k%d", edCounter)
}

func list(lines ...string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
