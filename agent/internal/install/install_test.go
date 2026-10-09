package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssh-buddy/agent/internal/agent"
)

type call struct{ name, args string }

// fakeRunner scripts sshd/systemctl behaviour and records every call.
type fakeRunner struct {
	calls         []call
	sshdT         func(n int) error // n counts "sshd -t" invocations
	tCount        int
	effective     string
	failTT        bool
	failReload    bool
	failDisable   bool
	inactive      bool
	failStart     bool
	dropInAtSshdT []string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	a := strings.Join(args, " ")
	f.calls = append(f.calls, call{name, a})
	switch {
	case name == "sshd" && a == "-t":
		f.tCount++
		if f.sshdT != nil {
			return "", f.sshdT(f.tCount)
		}
		return "", nil
	case name == "sshd" && strings.HasPrefix(a, "-T"):
		if f.failTT {
			return "", errors.New("sshd: no hostkeys available")
		}
		if f.effective != "" {
			return f.effective, nil
		}
		return "port 22\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/authorized_keys.d/%u-managed\n", nil
	case name == "systemctl" && strings.HasPrefix(a, "reload"):
		if f.failReload || f.inactive {
			return "", errors.New("reload failed")
		}
	case name == "systemctl" && strings.HasPrefix(a, "is-active"):
		if f.inactive {
			return "", errors.New("inactive")
		}
	case name == "systemctl" && strings.HasPrefix(a, "start"):
		if f.failStart {
			return "", errors.New("start failed")
		}
	case name == "systemctl" && strings.HasPrefix(a, "disable"):
		if f.failDisable {
			return "", errors.New("cannot disable")
		}
	}
	return "", nil
}

func (f *fakeRunner) ran(name, args string) bool {
	for _, c := range f.calls {
		if c.name == name && c.args == args {
			return true
		}
	}
	return false
}

type fixture struct {
	in  *Installer
	r   *fakeRunner
	dir string
	log *strings.Builder
}

func newFixture(t *testing.T, systemd bool) *fixture {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sbin", "ssh-buddy-agent")
	must(t, os.MkdirAll(filepath.Dir(bin), 0o755))
	must(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))
	runDir := filepath.Join(dir, "run-systemd-system")
	if systemd {
		must(t, os.MkdirAll(runDir, 0o755))
	}
	r := &fakeRunner{}
	log := &strings.Builder{}
	return &fixture{
		dir: dir, r: r, log: log,
		in: &Installer{
			Config:        agent.Config{BaseURL: "https://keys.example.com", Interval: 7 * time.Minute},
			Owner:         agent.Owner{UID: os.Getuid(), GID: os.Getgid()},
			BinaryPath:    bin,
			ManagedFile:   filepath.Join(dir, "ssh", "authorized_keys.d", "root-managed"),
			DropIn:        filepath.Join(dir, "ssh", "sshd_config.d", "10-ssh-buddy.conf"),
			SystemdDir:    filepath.Join(dir, "systemd"),
			SystemdRunDir: runDir,
			PrivSepDir:    filepath.Join(dir, "run", "sshd"),
			Run:           r,
			Log:           log,
		},
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) read(path string) (string, bool) {
	b, err := os.ReadFile(path)
	return string(b), err == nil
}

func TestInstallWritesDropInAndUnitsAndVerifiesSshd(t *testing.T) {
	f := newFixture(t, true)
	must(t, f.in.Install())

	if got, _ := f.read(f.in.DropIn); got != DropInContent {
		t.Errorf("drop-in = %q", got)
	}
	svc, _ := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.service"))
	for _, want := range []string{"ExecStart=" + f.in.BinaryPath + " sync", "network-online.target", "Type=oneshot"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service lacks %q:\n%s", want, svc)
		}
	}
	if strings.Contains(svc, "SuccessExitStatus") {
		t.Error("exit codes must not be mapped to success: systemd then reports status 0 and callers cannot see a failed report")
	}
	timer, _ := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.timer"))
	for _, want := range []string{"OnUnitActiveSec=7min", "RandomizedDelaySec=30s", "OnBootSec=2min", "WantedBy=timers.target"} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer lacks %q:\n%s", want, timer)
		}
	}
	if !f.r.ran("sshd", "-T -C user=root,host=localhost,addr=127.0.0.1") {
		t.Error("effective sshd configuration was not verified")
	}
	if !f.r.ran("systemctl", "daemon-reload") || !f.r.ran("systemctl", "reload ssh") {
		t.Errorf("calls: %v", f.r.calls)
	}
	if f.r.ran("systemctl", "enable --now ssh-buddy-agent.timer") {
		t.Error("install must not enable the timer; the bootstrap does that after the first sync")
	}
	fi, _ := os.Stat(filepath.Dir(f.in.ManagedFile))
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("managed dir mode %v", fi.Mode().Perm())
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	f := newFixture(t, true)
	must(t, f.in.Install())
	must(t, f.in.Install())
	if got, _ := f.read(f.in.DropIn); got != DropInContent {
		t.Error("drop-in changed on second install")
	}
}

func TestFailedValidationRollsBackToNoDropIn(t *testing.T) {
	f := newFixture(t, true)
	f.r.sshdT = func(n int) error {
		if n == 2 { // the first -t is the baseline check; the second validates our drop-in
			return errors.New("/etc/ssh/sshd_config.d/10-ssh-buddy.conf: bad configuration")
		}
		return nil
	}
	err := f.in.Install()
	if err == nil || !strings.Contains(err.Error(), "sshd rejected") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("the drop-in must be removed again (there was none before)")
	}
	if _, ok := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.service")); ok {
		t.Error("units must not be written when sshd validation fails")
	}
	if f.r.tCount < 3 {
		t.Error("sshd -t should be re-run after rolling back")
	}
}

func TestFailedValidationRestoresAPreviousDropInExactly(t *testing.T) {
	f := newFixture(t, true)
	must(t, os.MkdirAll(filepath.Dir(f.in.DropIn), 0o755))
	previous := "# my own setting\nAuthorizedKeysFile .ssh/authorized_keys\n"
	must(t, os.WriteFile(f.in.DropIn, []byte(previous), 0o640))
	f.r.sshdT = func(n int) error {
		if n == 2 {
			return errors.New("invalid")
		}
		return nil
	}
	if err := f.in.Install(); err == nil {
		t.Fatal("expected failure")
	}
	got, _ := f.read(f.in.DropIn)
	fi, _ := os.Stat(f.in.DropIn)
	if got != previous || fi.Mode().Perm() != 0o640 {
		t.Errorf("previous drop-in not restored exactly: %q %v", got, fi.Mode().Perm())
	}
}

func TestOverriddenAuthorizedKeysFileIsAnInstallFailureNotAWarning(t *testing.T) {
	cases := map[string]string{
		"overridden by another drop-in": "authorizedkeysfile .ssh/authorized_keys\n",
		"recovery path missing":         "authorizedkeysfile /etc/ssh/authorized_keys.d/%u-managed\n",
		"unrelated file":                "authorizedkeysfile /srv/keys/%u\n",
		"missing entirely":              "port 22\n",
	}
	for name, effective := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, true)
			f.r.effective = effective
			err := f.in.Install()
			if err == nil {
				t.Fatal("install succeeded although the managed file would not be honoured")
			}
			if _, ok := f.read(f.in.DropIn); ok {
				t.Error("drop-in left behind")
			}
			if _, ok := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.timer")); ok {
				t.Error("units left behind")
			}
		})
	}
}

func TestMissingHostKeysGiveAClearError(t *testing.T) {
	f := newFixture(t, true)
	f.r.failTT = true
	err := f.in.Install()
	if err == nil || !strings.Contains(err.Error(), "ssh-keygen -A") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("drop-in left behind")
	}
}

func TestAlreadyBrokenSshdIsLeftAlone(t *testing.T) {
	f := newFixture(t, true)
	f.r.sshdT = func(int) error { return errors.New("broken before we started") }
	err := f.in.Install()
	if err == nil || !strings.Contains(err.Error(), "already invalid") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("touched an sshd configuration that was already broken")
	}
}

func TestReloadFailureRollsBackEverythingAndReloadsAgain(t *testing.T) {
	f := newFixture(t, true)
	f.r.failReload = true
	if err := f.in.Install(); err == nil {
		t.Fatal("expected failure")
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("drop-in left behind")
	}
	if _, ok := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.service")); ok {
		t.Error("unit left behind")
	}
}

func TestLegacyShellTimerIsDisabledToAvoidTwoWriters(t *testing.T) {
	f := newFixture(t, true)
	must(t, os.MkdirAll(f.in.SystemdDir, 0o755))
	must(t, os.WriteFile(filepath.Join(f.in.SystemdDir, "ssh-buddy-sync.timer"), []byte("[Timer]\n"), 0o644))
	must(t, f.in.Install())
	if !f.r.ran("systemctl", "disable --now ssh-buddy-sync.timer") {
		t.Errorf("legacy timer not disabled: %v", f.r.calls)
	}
}

func TestNoLegacyTimerMeansNoDisableCall(t *testing.T) {
	f := newFixture(t, true)
	must(t, f.in.Install())
	if f.r.ran("systemctl", "disable --now ssh-buddy-sync.timer") {
		t.Error("unexpected disable")
	}
}

func TestLegacyDisableFailureFailsTheInstall(t *testing.T) {
	f := newFixture(t, true)
	must(t, os.MkdirAll(f.in.SystemdDir, 0o755))
	must(t, os.WriteFile(filepath.Join(f.in.SystemdDir, "ssh-buddy-sync.timer"), []byte("[Timer]\n"), 0o644))
	f.r.failDisable = true
	if err := f.in.Install(); err == nil {
		t.Fatal("expected failure")
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("drop-in left behind")
	}
}

func TestWithoutRunningSystemdOnlyFilesAreWritten(t *testing.T) {
	f := newFixture(t, false)
	must(t, f.in.Install())
	for _, c := range f.r.calls {
		if c.name == "systemctl" {
			t.Errorf("systemctl called without systemd: %v", c)
		}
	}
	if _, ok := f.read(filepath.Join(f.in.SystemdDir, "ssh-buddy-agent.service")); !ok {
		t.Error("unit not written")
	}
}

func TestMissingBinaryIsRefused(t *testing.T) {
	f := newFixture(t, true)
	must(t, os.Remove(f.in.BinaryPath))
	if err := f.in.Install(); err == nil {
		t.Fatal("expected failure")
	}
	if len(f.r.calls) != 0 {
		t.Error("should fail before running anything")
	}
}

func TestSystemdDurationFormatting(t *testing.T) {
	for d, want := range map[time.Duration]string{5 * time.Minute: "5min", 90 * time.Second: "90s", 24 * time.Hour: "1440min"} {
		if got := systemdDuration(d); got != want {
			t.Errorf("%v -> %q, want %q", d, got, want)
		}
	}
	_ = fmt.Sprint
}

func TestPrivilegeSeparationDirectoryIsCreatedBeforeSshdIsAskedToValidate(t *testing.T) {
	f := newFixture(t, true)
	f.r.sshdT = func(int) error {
		if _, err := os.Stat(f.in.PrivSepDir); err != nil {
			return errors.New("Missing privilege separation directory")
		}
		return nil
	}
	must(t, f.in.Install())
}

func TestAnInactiveSshServiceIsStartedInsteadOfReloaded(t *testing.T) {
	f := newFixture(t, true)
	f.r.inactive = true
	must(t, f.in.Install())
	if !f.r.ran("systemctl", "start ssh") {
		t.Errorf("ssh.service was not started: %v", f.r.calls)
	}
}

func TestInstallFailsIfSshCanNeitherBeReloadedNorStarted(t *testing.T) {
	f := newFixture(t, true)
	f.r.inactive, f.r.failStart = true, true
	if err := f.in.Install(); err == nil {
		t.Fatal("expected failure")
	}
	if _, ok := f.read(f.in.DropIn); ok {
		t.Error("drop-in left behind")
	}
}
