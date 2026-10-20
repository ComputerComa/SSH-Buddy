package agent

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func (e *env) sync() (SyncResult, error) {
	return e.agent.Sync(context.Background())
}

func TestFirstSyncInstallsKeysWithRootOwnedPermissionsAndNoTempFiles(t *testing.T) {
	e := newEnv(t)
	body := list(newKey(t), newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = body })

	res, err := e.sync()
	if err != nil || !res.Changed || res.KeyCount != 2 {
		t.Fatalf("sync = %+v, %v", res, err)
	}
	if got := e.managed(); got != body {
		t.Fatalf("managed file = %q", got)
	}
	fi, _ := os.Stat(e.agent.Paths.ManagedFile)
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("file mode = %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(e.agent.Paths.ManagedFile))
	if di.Mode().Perm() != 0o755 {
		t.Errorf("dir mode = %v", di.Mode().Perm())
	}
	if res.AppliedETag != etagOf(body) {
		t.Errorf("applied etag = %q", res.AppliedETag)
	}
	if l := e.leftovers(); len(l) != 0 {
		t.Errorf("temp files left: %v", l)
	}
	reqs, _, _ := e.srv.snapshot()
	if reqs[0].Get("If-None-Match") != "" {
		t.Error("first request must be unconditional")
	}
}

func TestSecondSyncUsesETagAndLeavesTheFileUntouched(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	_, err := e.sync()
	must(t, err)
	ino := e.inode(e.agent.Paths.ManagedFile)
	fi, _ := os.Stat(e.agent.Paths.ManagedFile)
	mtime := fi.ModTime()
	time.Sleep(20 * time.Millisecond)

	res, err := e.sync()
	if err != nil || !res.NotModified || res.Changed {
		t.Fatalf("second sync = %+v, %v", res, err)
	}
	reqs, _, _ := e.srv.snapshot()
	if got := reqs[len(reqs)-1].Get("If-None-Match"); got != etagOf(e.srv.keyBody) {
		t.Errorf("If-None-Match = %q", got)
	}
	fi2, _ := os.Stat(e.agent.Paths.ManagedFile)
	if e.inode(e.agent.Paths.ManagedFile) != ino || !fi2.ModTime().Equal(mtime) {
		t.Error("file was rewritten although nothing changed")
	}
	if res.AppliedETag != etagOf(e.srv.keyBody) {
		t.Errorf("applied etag = %q", res.AppliedETag)
	}
}

func TestChangedListIsReplacedAtomicallyByRename(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	_, err := e.sync()
	must(t, err)
	before := e.inode(e.agent.Paths.ManagedFile)

	next := list(newKey(t), newKey(t), newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = next })
	res, err := e.sync()
	if err != nil || !res.Changed || res.KeyCount != 3 {
		t.Fatalf("sync = %+v, %v", res, err)
	}
	if e.managed() != next {
		t.Fatal("content not updated")
	}
	if e.inode(e.agent.Paths.ManagedFile) == before {
		t.Error("same inode: the file was rewritten in place instead of replaced by rename")
	}
	if l := e.leftovers(); len(l) != 0 {
		t.Errorf("temp files left: %v", l)
	}
}

func TestEmptyListClearsTheManagedFileAndIsCachedLikeAnyOther(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	_, err := e.sync()
	must(t, err)

	e.srv.set(func(f *fakeServer) { f.keyBody = "" })
	res, err := e.sync()
	if err != nil || !res.Changed || res.KeyCount != 0 {
		t.Fatalf("sync = %+v, %v", res, err)
	}
	if got := e.managed(); got != "" {
		t.Fatalf("managed file = %q, want empty", got)
	}
	// an empty file is still a validated local state, so the next run may be conditional and gets a 304
	res, err = e.sync()
	if err != nil || !res.NotModified {
		t.Fatalf("after clearing: %+v, %v", res, err)
	}
}

func TestEmptyListOnAFreshMachineCreatesAnEmptyFile(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = "" })
	if _, err := e.sync(); err != nil {
		t.Fatal(err)
	}
	if got := e.managed(); got != "" {
		t.Fatalf("managed = %q", got)
	}
}

func TestRecoveryKeysAreNeverTouched(t *testing.T) {
	e := newEnv(t)
	recovery := filepath.Join(e.dir, "root", ".ssh", "authorized_keys")
	must(t, os.MkdirAll(filepath.Dir(recovery), 0o700))
	content := list(newKey(t))
	must(t, os.WriteFile(recovery, []byte(content), 0o600))
	fi, _ := os.Stat(recovery)

	for _, body := range []string{list(newKey(t)), "", list(newKey(t), newKey(t))} {
		e.srv.set(func(f *fakeServer) { f.keyBody = body })
		_, err := e.sync()
		must(t, err)
	}
	e.srv.set(func(f *fakeServer) { f.keyStatus = 500 })
	_, _ = e.sync()

	got, _ := os.ReadFile(recovery)
	fi2, _ := os.Stat(recovery)
	if string(got) != content || !fi2.ModTime().Equal(fi.ModTime()) || fi2.Mode() != fi.Mode() {
		t.Error("the recovery file changed")
	}
}

// ---- ETag / cache trust

func TestNotModifiedIsOnlyTrustedWhileLocalContentsMatchTheCachedETag(t *testing.T) {
	cases := map[string]func(e *env){
		"file altered": func(e *env) {
			must(t, os.WriteFile(e.agent.Paths.ManagedFile, []byte(list(newKey(t))), 0o644)) // valid, but not what the ETag describes
		},
		"file corrupted": func(e *env) { must(t, os.WriteFile(e.agent.Paths.ManagedFile, []byte("garbage\n"), 0o644)) },
		"file deleted":   func(e *env) { must(t, os.Remove(e.agent.Paths.ManagedFile)) },
		"state deleted":  func(e *env) { must(t, os.Remove(filepath.Join(e.agent.Paths.StateDir, "state.json"))) },
		"state garbage": func(e *env) {
			must(t, os.WriteFile(filepath.Join(e.agent.Paths.StateDir, "state.json"), []byte("{nope"), 0o600))
		},
		"file is symlink": func(e *env) {
			real := filepath.Join(e.dir, "elsewhere")
			must(t, os.WriteFile(real, []byte(e.srv.keyBody), 0o644))
			must(t, os.Remove(e.agent.Paths.ManagedFile))
			must(t, os.Symlink(real, e.agent.Paths.ManagedFile))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			want := list(newKey(t), newKey(t))
			e.srv.set(func(f *fakeServer) { f.keyBody = want })
			_, err := e.sync()
			must(t, err)

			tamper(e)
			before, _, _ := e.srv.snapshot()
			res, err := e.sync()
			if err != nil {
				t.Fatalf("sync failed: %v", err)
			}
			reqs, _, _ := e.srv.snapshot()
			last := reqs[len(reqs)-1]
			if len(reqs) != len(before)+1 || last.Get("If-None-Match") != "" {
				t.Errorf("expected an unconditional fetch, got If-None-Match=%q", last.Get("If-None-Match"))
			}
			if res.NotModified {
				t.Error("must not report not-modified")
			}
			if e.managed() != want {
				t.Errorf("file was not restored to the server's list: %q", e.managed())
			}
			if fi, err := os.Lstat(e.agent.Paths.ManagedFile); err != nil || !fi.Mode().IsRegular() {
				t.Error("managed file is not a regular file after sync")
			}
		})
	}
}

func TestAServerThatAnswers304ToAnUnconditionalRequestIsAnError(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.alwaysNM = true; f.keyBody = list(newKey(t)) })
	_, err := e.sync()
	if err == nil || !strings.Contains(err.Error(), "304") {
		t.Fatalf("err = %v", err)
	}
	if e.managed() != "<missing>" {
		t.Error("a file appeared although nothing was validated")
	}
}

func TestPermissionsAreRepairedOnNotModified(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	_, err := e.sync()
	must(t, err)
	must(t, os.Chmod(e.agent.Paths.ManagedFile, 0o666))
	must(t, os.Chmod(filepath.Dir(e.agent.Paths.ManagedFile), 0o775))

	res, err := e.sync()
	if err != nil || !res.NotModified {
		t.Fatalf("%+v %v", res, err)
	}
	fi, _ := os.Stat(e.agent.Paths.ManagedFile)
	di, _ := os.Stat(filepath.Dir(e.agent.Paths.ManagedFile))
	if fi.Mode().Perm() != 0o644 || di.Mode().Perm() != 0o755 {
		t.Errorf("file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
	}
}

// ---- failure handling: the existing file always survives

func TestFailuresKeepTheExistingKeysAndState(t *testing.T) {
	good := list(newKey(t), newKey(t))
	cases := map[string]func(f *fakeServer){
		"http 500":            func(f *fakeServer) { f.keyStatus = 500 },
		"http 404":            func(f *fakeServer) { f.keyStatus = 404 },
		"http 403":            func(f *fakeServer) { f.keyStatus = 403 },
		"http 204":            func(f *fakeServer) { f.keyStatus = 204 },
		"redirect":            func(f *fakeServer) { f.keyStatus = 302 },
		"html with 200":       func(f *fakeServer) { f.keyBody = "<html>captive portal</html>\n"; f.ignoreINM = true },
		"options in list":     func(f *fakeServer) { f.keyBody = `command="/bin/evil" ` + newKey(t) + "\n"; f.ignoreINM = true },
		"one bad line":        func(f *fakeServer) { f.keyBody = good + "ssh-ed25519 AAAA bad\n"; f.ignoreINM = true },
		"no trailing newline": func(f *fakeServer) { f.keyBody = strings.TrimSuffix(good, "\n") + "x"; f.ignoreINM = true },
		"oversize":            func(f *fakeServer) { f.keyBody = strings.Repeat(newKey(t)+"\n", 14000); f.ignoreINM = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.set(func(f *fakeServer) { f.keyBody = good })
			_, err := e.sync()
			must(t, err)
			stateBefore, _ := os.ReadFile(filepath.Join(e.agent.Paths.StateDir, "state.json"))
			ino := e.inode(e.agent.Paths.ManagedFile)

			e.srv.set(mutate)
			res, err := e.sync()
			if err == nil {
				t.Fatalf("expected an error, got %+v", res)
			}
			if e.managed() != good || e.inode(e.agent.Paths.ManagedFile) != ino {
				t.Error("existing keys were modified")
			}
			stateAfter, _ := os.ReadFile(filepath.Join(e.agent.Paths.StateDir, "state.json"))
			if string(stateBefore) != string(stateAfter) {
				t.Error("state changed on failure")
			}
			// the applied ETag of the still-valid local contents is reported even though this run failed
			if res.AppliedETag != etagOf(good) {
				t.Errorf("applied etag on failure = %q", res.AppliedETag)
			}
			if l := e.leftovers(); len(l) != 0 {
				t.Errorf("temp files left: %v", l)
			}
		})
	}
}

func TestNetworkFailureKeepsTheExistingKeys(t *testing.T) {
	e := newEnv(t)
	good := list(newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = good })
	_, err := e.sync()
	must(t, err)
	e.srv.Close()

	if _, err := e.sync(); err == nil {
		t.Fatal("expected a connection error")
	}
	if e.managed() != good {
		t.Error("existing keys changed")
	}
}

func TestSlowServerIsAbandonedWithinTheTimeout(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)); f.sleep = func() { time.Sleep(2 * time.Second) } })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := e.agent.Sync(ctx); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > time.Second {
		t.Error("did not give up promptly")
	}
	if e.managed() != "<missing>" {
		t.Error("a file appeared")
	}
}

func TestCertificateVerificationIsNeverDisabled(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	// the production client trusts only the system roots, which do not include the test server's CA
	e.agent.HTTP = NewHTTPClient(nil)
	_, err := e.sync()
	if err == nil {
		t.Fatal("sync succeeded against an untrusted certificate")
	}
	var unknown x509.UnknownAuthorityError
	if !strings.Contains(err.Error(), "certificate") && !errorsAs(err, &unknown) {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.managed() != "<missing>" {
		t.Error("keys were installed over an unverified connection")
	}
}

func TestSchemeComesOnlyFromTheConfig(t *testing.T) {
	for _, u := range []string{"https://keys.example.com", "http://keys.example.com"} {
		c := Config{BaseURL: u + "/", Interval: DefaultInterval}
		if err := c.Validate(); err != nil || c.BaseURL != u {
			t.Errorf("%s -> %q, %v", u, c.BaseURL, err)
		}
	}
}

// ---- lock

func TestOverlappingRunsAreRefusedWithoutAnyNetworkTraffic(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	lock, err := AcquireLock(e.agent.Paths.LockFile)
	must(t, err)
	defer lock.Close()

	if code := e.agent.Run(context.Background()); code != ExitBusy {
		t.Fatalf("exit = %d, want %d", code, ExitBusy)
	}
	reqs, enr, ci := e.srv.snapshot()
	if len(reqs)+len(enr)+len(ci) != 0 {
		t.Error("a busy run still talked to the server")
	}
	lock.Close()
	if code := e.agent.Run(context.Background()); code != ExitOK {
		t.Fatalf("exit after release = %d", code)
	}
}

func TestConcurrentRunsOnlyOneProceeds(t *testing.T) {
	e := newEnv(t)
	var inflight, maxInflight int32
	e.srv.set(func(f *fakeServer) {
		f.keyBody = list(newKey(t))
		f.sleep = func() {
			n := atomic.AddInt32(&inflight, 1)
			for {
				m := atomic.LoadInt32(&maxInflight)
				if n <= m || atomic.CompareAndSwapInt32(&maxInflight, m, n) {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
			atomic.AddInt32(&inflight, -1)
		}
	})
	codes := make(chan int, 4)
	for i := 0; i < 4; i++ {
		go func() {
			a := *e.agent // each real run is its own process with its own log
			a.Log = io.Discard
			codes <- a.Run(context.Background())
		}()
	}
	busy, ok := 0, 0
	for i := 0; i < 4; i++ {
		switch <-codes {
		case ExitBusy:
			busy++
		case ExitOK:
			ok++
		}
	}
	if maxInflight != 1 || ok < 1 || busy < 1 {
		t.Errorf("max concurrent key fetches=%d ok=%d busy=%d", maxInflight, ok, busy)
	}
}

func errorsAs(err error, target *x509.UnknownAuthorityError) bool {
	for err != nil {
		if e, ok := err.(x509.UnknownAuthorityError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
