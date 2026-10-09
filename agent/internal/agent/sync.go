package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ssh-buddy/agent/internal/keys"
)

// State is the agent's persisted view of what it last applied. The ETag is only trusted while the managed
// file still hashes to Sha256, i.e. while the local content is exactly what that ETag described.
type State struct {
	ETag        string `json:"etag"`
	Sha256      string `json:"sha256"`
	FirstSyncOK bool   `json:"first_sync_ok"`
}

// SyncResult describes one synchronization attempt.
type SyncResult struct {
	Changed     bool
	NotModified bool
	KeyCount    int
	// AppliedETag is the ETag of the validated contents currently in the managed file ("" when unknown).
	AppliedETag string
}

func (a *Agent) statePath() string { return filepath.Join(a.Paths.StateDir, "state.json") }

func (a *Agent) loadState() State {
	b, err := os.ReadFile(a.statePath())
	if err != nil {
		return State{}
	}
	var s State
	if json.Unmarshal(b, &s) != nil {
		return State{} // unreadable state is treated as no state: fetch unconditionally
	}
	return s
}

func (a *Agent) saveState(s State) error {
	b, _ := json.Marshal(s)
	return WriteFileAtomic(a.statePath(), append(b, '\n'), 0o600, a.Owner, 0o700)
}

// localContents returns the managed file's bytes if (and only if) it exists, is a regular file, validates,
// and matches the hash recorded with the cached ETag.
func (a *Agent) localContents(st State) (data []byte, trusted bool) {
	data, err := readRegular(a.Paths.ManagedFile, keys.MaxBytes)
	if err != nil {
		return nil, false
	}
	if _, err := keys.ParseList(data); err != nil {
		return data, false
	}
	return data, st.ETag != "" && st.Sha256 == sha256Hex(data)
}

// Sync downloads, validates and (only when it differs) atomically installs the global key list.
// On any error the existing managed file and state are left untouched.
func (a *Agent) Sync(ctx context.Context) (SyncResult, error) {
	st := a.loadState()
	local, trusted := a.localContents(st)

	// The ETag reported to the server is the one of the validated local contents, even if this run fails.
	res := SyncResult{}
	if trusted {
		res.AppliedETag = st.ETag
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Config.BaseURL+"/api/authorized-keys", nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "ssh-buddy-agent/"+a.Version)
	sentConditional := false
	if trusted {
		req.Header.Set("If-None-Match", st.ETag)
		sentConditional = true
	}

	resp, err := a.HTTP.Do(req)
	if err != nil {
		return res, fmt.Errorf("fetching key list: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if !sentConditional {
			return res, errors.New("server answered 304 to an unconditional request")
		}
		// Local contents were validated above and match the cached ETag: nothing to write, but keep metadata right.
		if err := a.fixMeta(); err != nil {
			return res, err
		}
		n, _ := keys.ParseList(local)
		res.NotModified, res.KeyCount = true, n
		return res, nil

	case http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, keys.MaxBytes+1))
		if err != nil {
			return res, fmt.Errorf("reading key list: %w", err)
		}
		if len(body) > keys.MaxBytes {
			return res, fmt.Errorf("key list exceeds %d bytes", keys.MaxBytes)
		}
		n, err := keys.ParseList(body)
		if err != nil {
			return res, fmt.Errorf("rejecting key list: %w", err)
		}
		etag := resp.Header.Get("ETag")
		if !validETag(etag) {
			etag = "" // usable content, but no conditional requests next time
		}

		if bytes.Equal(local, body) && local != nil {
			// Content is already exactly right (e.g. state was lost): only repair mode/ownership.
			if err := a.fixMeta(); err != nil {
				return res, err
			}
		} else {
			if err := WriteFileAtomic(a.Paths.ManagedFile, body, 0o644, a.Owner, 0o755); err != nil {
				return res, fmt.Errorf("installing key list: %w", err)
			}
			res.Changed = true
		}

		// State is written before any reporting, so a reporting failure can never affect it.
		if err := a.saveState(State{ETag: etag, Sha256: sha256Hex(body), FirstSyncOK: true}); err != nil {
			return res, fmt.Errorf("saving state: %w", err)
		}
		res.KeyCount = n
		res.AppliedETag = etag
		return res, nil

	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return res, fmt.Errorf("unexpected HTTP %d from key list endpoint", resp.StatusCode)
	}
}

func (a *Agent) fixMeta() error {
	if err := ensureDir(filepath.Dir(a.Paths.ManagedFile), 0o755, a.Owner); err != nil {
		return err
	}
	return ensureFileMeta(a.Paths.ManagedFile, 0o644, a.Owner)
}

func validETag(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return !strings.ContainsAny(s, "\r\n")
}
