// Package install configures sshd and systemd for the agent, transactionally: any failure restores the
// previous state exactly (including "there was no drop-in before").
package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssh-buddy/agent/internal/agent"
)

// DropInContent keeps Debian's default per-user files (so /root/.ssh/authorized_keys, the recovery file, is still
// honoured) and adds the managed list. %u limits the managed file to users that have one: only root-managed exists.
const DropInContent = `# Managed by ssh-buddy-agent. Keeps the default per-user files (including root's recovery file)
# and adds the centrally managed list. %u restricts it to users that have such a file: only root-managed exists.
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/authorized_keys.d/%u-managed
`

const (
	recoveryEntry = ".ssh/authorized_keys"
	managedEntry  = "/etc/ssh/authorized_keys.d/%u-managed"
)

// Runner executes external commands (sshd, systemctl); tests substitute a fake.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// ExecRunner runs real commands with a timeout.
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return string(out), fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Installer holds the locations it modifies.
type Installer struct {
	Config      agent.Config
	Owner       agent.Owner
	BinaryPath  string
	ManagedFile string
	DropIn      string
	SystemdDir  string
	// SystemdRunDir exists only while systemd is the running init (/run/systemd/system).
	SystemdRunDir string
	// PrivSepDir is sshd's privilege-separation directory. ssh.service creates it when it starts, but on a
	// clone's first boot the bootstrap runs before (or without) a successful ssh.service, and `sshd -t` fails without it.
	PrivSepDir string
	Run        Runner
	Log        io.Writer
}

// Defaults returns an Installer for production paths.
func Defaults(cfg agent.Config, p agent.Paths) *Installer {
	return &Installer{
		Config:        cfg,
		Owner:         agent.Owner{},
		BinaryPath:    "/usr/local/sbin/ssh-buddy-agent",
		ManagedFile:   p.ManagedFile,
		DropIn:        "/etc/ssh/sshd_config.d/10-ssh-buddy.conf",
		SystemdDir:    "/etc/systemd/system",
		SystemdRunDir: "/run/systemd/system",
		PrivSepDir:    "/run/sshd",
		Run:           ExecRunner{},
		Log:           os.Stderr,
	}
}

type snapshot struct {
	path    string
	existed bool
	data    []byte
	mode    os.FileMode
}

func takeSnapshot(path string) (snapshot, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot{path: path}, nil
	}
	if err != nil {
		return snapshot{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{path: path, existed: true, data: data, mode: fi.Mode().Perm()}, nil
}

func (s snapshot) restore(owner agent.Owner) error {
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return agent.WriteFileAtomic(s.path, s.data, s.mode, owner, 0o755)
}

func (in *Installer) logf(format string, args ...any) {
	fmt.Fprintf(in.Log, "ssh-buddy-agent install: "+format+"\n", args...)
}

func (in *Installer) systemdRunning() bool {
	_, err := os.Stat(in.SystemdRunDir)
	return err == nil
}

// Install applies the configuration. It does not enable the timer: the bootstrap does that after the first sync.
func (in *Installer) Install() (err error) {
	if _, statErr := os.Stat(in.BinaryPath); statErr != nil {
		return fmt.Errorf("the agent binary must be installed at %s first: %w", in.BinaryPath, statErr)
	}
	if in.PrivSepDir != "" {
		if err := os.MkdirAll(in.PrivSepDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", in.PrivSepDir, err)
		}
	}
	if _, err := in.Run.Run("sshd", "-t"); err != nil {
		return fmt.Errorf("the existing sshd configuration is already invalid; refusing to change it: %w", err)
	}

	var snaps []snapshot
	sshChanged, reloaded := false, false
	defer func() {
		if err == nil {
			return
		}
		in.logf("FAILED, rolling back: %v", err)
		for i := len(snaps) - 1; i >= 0; i-- {
			if rerr := snaps[i].restore(in.Owner); rerr != nil {
				in.logf("rollback of %s failed: %v", snaps[i].path, rerr)
			}
		}
		if sshChanged {
			if _, terr := in.Run.Run("sshd", "-t"); terr != nil {
				in.logf("WARNING: sshd -t fails after rollback: %v", terr)
			}
			if reloaded && in.systemdRunning() {
				if rerr := in.reloadSSH(); rerr != nil {
					in.logf("WARNING: reloading sshd after rollback failed: %v", rerr)
				}
			}
		}
	}()
	write := func(path, content string) error {
		s, serr := takeSnapshot(path)
		if serr != nil {
			return serr
		}
		snaps = append(snaps, s)
		return agent.WriteFileAtomic(path, []byte(content), 0o644, in.Owner, 0o755)
	}

	// 1. sshd drop-in, validated and verified before anything else is touched.
	if err = write(in.DropIn, DropInContent); err != nil {
		return err
	}
	sshChanged = true
	if _, err = in.Run.Run("sshd", "-t"); err != nil {
		return fmt.Errorf("sshd rejected the configuration: %w", err)
	}
	if err = in.verifyEffective(); err != nil {
		return err
	}

	// 2. the directory sshd reads the managed file from (sshd's StrictModes wants it root-owned and not writable by others)
	if err = os.MkdirAll(filepath.Dir(in.ManagedFile), 0o755); err != nil {
		return err
	}
	if err = os.Chmod(filepath.Dir(in.ManagedFile), 0o755); err != nil {
		return err
	}
	if err = os.Chown(filepath.Dir(in.ManagedFile), in.Owner.UID, in.Owner.GID); err != nil {
		return err
	}

	// 3. systemd units
	if err = write(filepath.Join(in.SystemdDir, "ssh-buddy-agent.service"), in.serviceUnit()); err != nil {
		return err
	}
	if err = write(filepath.Join(in.SystemdDir, "ssh-buddy-agent.timer"), in.timerUnit()); err != nil {
		return err
	}

	if !in.systemdRunning() {
		in.logf("systemd is not running (container build or chroot?): units written, nothing reloaded")
		return nil
	}
	if _, err = in.Run.Run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Two writers on the same file would fight; the legacy shell client must not keep running.
	if _, statErr := os.Stat(filepath.Join(in.SystemdDir, "ssh-buddy-sync.timer")); statErr == nil {
		in.logf("disabling the legacy ssh-buddy-sync.timer (superseded by this agent)")
		if _, err = in.Run.Run("systemctl", "disable", "--now", "ssh-buddy-sync.timer"); err != nil {
			return err
		}
	}
	reloaded = true
	if err = in.reloadSSH(); err != nil {
		return err
	}
	in.logf("installed; the timer is not enabled yet (run: systemctl enable --now ssh-buddy-agent.timer)")
	return nil
}

// reloadSSH makes sshd pick up the new configuration. A unit that is not running (for example because it failed
// earlier for lack of host keys) cannot be reloaded, but starting it reads the new configuration anyway.
func (in *Installer) reloadSSH() error {
	var firstErr error
	for _, unit := range []string{"ssh", "sshd"} {
		_, err := in.Run.Run("systemctl", "reload", unit)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if _, activeErr := in.Run.Run("systemctl", "is-active", "--quiet", unit); activeErr != nil {
			if _, startErr := in.Run.Run("systemctl", "start", unit); startErr == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("reloading sshd: %w", firstErr)
}

// verifyEffective asks sshd for the setting it will really use for root, and requires BOTH the recovery file and
// the managed file: another drop-in sorting earlier would silently win otherwise.
func (in *Installer) verifyEffective() error {
	out, err := in.Run.Run("sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1")
	if err != nil {
		return fmt.Errorf("cannot read sshd's effective configuration (missing host keys? run ssh-keygen -A): %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "authorizedkeysfile") {
			continue
		}
		have := map[string]bool{}
		for _, f := range fields[1:] {
			have[f] = true
		}
		if have[recoveryEntry] && have[managedEntry] {
			return nil
		}
		return fmt.Errorf("sshd's effective AuthorizedKeysFile is %q; it must include both %s and %s. "+
			"Another sshd_config setting overrides the drop-in", strings.Join(fields[1:], " "), recoveryEntry, managedEntry)
	}
	return errors.New("sshd -T did not report an AuthorizedKeysFile setting")
}

func (in *Installer) serviceUnit() string {
	return fmt.Sprintf(`[Unit]
Description=SSH Buddy agent: sync authorized keys and report status
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=%s sync
TimeoutStartSec=180
# Exit codes: 1 = key sync failed, 3 = keys are fine but the status report failed, 4 = another run was active.
# Any non-zero exit leaves the unit "failed" (visible in systemctl --failed) without stopping the timer.
NoNewPrivileges=yes
`, in.BinaryPath)
}

func (in *Installer) timerUnit() string {
	return fmt.Sprintf(`[Unit]
Description=Run the SSH Buddy agent periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=%s
RandomizedDelaySec=30s
AccuracySec=10s

[Install]
WantedBy=timers.target
`, systemdDuration(in.Config.Interval))
}

func systemdDuration(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dmin", int(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}
