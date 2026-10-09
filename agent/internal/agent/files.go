package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Owner is the uid/gid files are chowned to. Production is root:root; tests use the current user.
type Owner struct{ UID, GID int }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// WriteFileAtomic writes data to path through a temporary file in the same directory, fsyncs it, then renames
// it into place and fsyncs the directory, so readers see the old or the new content, never a mixture.
func WriteFileAtomic(path string, data []byte, mode os.FileMode, owner Owner, dirMode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := ensureDir(dir, dirMode, owner); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chown(owner.UID, owner.GID); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ensureDir creates dir if needed and makes sure it is owned by owner and not writable by anyone else
// (sshd's StrictModes rejects key files under group/world-writable directories).
func ensureDir(dir string, mode os.FileMode, owner Owner) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm() != mode {
		if err := os.Chmod(dir, mode); err != nil {
			return err
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != owner.UID || int(st.Gid) != owner.GID) {
		if err := os.Chown(dir, owner.UID, owner.GID); err != nil {
			return err
		}
	}
	return nil
}

// ensureFileMeta repairs mode/ownership of an existing file without rewriting its content.
func ensureFileMeta(path string, mode os.FileMode, owner Owner) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm() != mode {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != owner.UID || int(st.Gid) != owner.GID) {
		return os.Chown(path, owner.UID, owner.GID)
	}
	return nil
}

// readRegular reads a regular file, refusing symlinks and special files.
func readRegular(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

// ErrBusy means another agent run holds the lock.
var ErrBusy = errors.New("another ssh-buddy-agent run is in progress")

// Lock is an exclusive, non-blocking, process-lifetime lock (flock), released on Close or process exit.
type Lock struct{ f *os.File }

func AcquireLock(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
