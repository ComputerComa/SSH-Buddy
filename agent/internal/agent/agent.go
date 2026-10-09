package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Exit codes of "sync".
const (
	ExitOK           = 0
	ExitSyncFailed   = 1 // keys could not be synchronized (the existing file is untouched)
	ExitUsage        = 2
	ExitReportFailed = 3 // keys are fine, but the status report did not get through
	ExitBusy         = 4 // another run holds the lock
)

// Agent bundles configuration and collaborators. Everything the tests need to vary is a field.
type Agent struct {
	Config   Config
	Paths    Paths
	Owner    Owner
	Version  string
	HTTP     *http.Client
	Hostname func() (string, error)
	Log      io.Writer
}

// NewHTTPClient builds the only HTTP client the agent uses: HTTPS, normal certificate verification against the
// system roots (or, in tests, an injected pool), TLS 1.2+, bounded timeouts and no redirects.
func NewHTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// New builds an Agent for production use.
func New(cfg Config, p Paths, version string) *Agent {
	return &Agent{
		Config:   cfg,
		Paths:    p,
		Owner:    Owner{UID: 0, GID: 0},
		Version:  version,
		HTTP:     NewHTTPClient(nil),
		Hostname: os.Hostname,
		Log:      os.Stderr,
	}
}

func (a *Agent) logf(format string, args ...any) {
	fmt.Fprintf(a.Log, "ssh-buddy-agent: "+format+"\n", args...)
}

// Run performs one full cycle: synchronize keys, then report. Reporting never influences synchronization,
// and a reporting failure never undoes a successful key update. It returns the process exit code.
func (a *Agent) Run(ctx context.Context) int {
	lock, err := AcquireLock(a.Paths.LockFile)
	if errors.Is(err, ErrBusy) {
		a.logf("another run is in progress; exiting")
		return ExitBusy
	}
	if err != nil {
		a.logf("ERROR: cannot take lock: %v", err)
		return ExitSyncFailed
	}
	defer lock.Close()

	syncCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	res, syncErr := a.Sync(syncCtx)
	cancel()
	switch {
	case syncErr != nil:
		a.logf("ERROR: sync failed, keeping existing keys: %v", syncErr)
	case res.NotModified:
		a.logf("keys unchanged (not modified, %d keys)", res.KeyCount)
	case res.Changed:
		a.logf("keys updated (%d keys)", res.KeyCount)
	default:
		a.logf("keys unchanged (%d keys)", res.KeyCount)
	}

	reportErr := a.report(ctx, res, syncErr)
	if reportErr != nil {
		a.logf("WARNING: status report failed: %v", reportErr)
	}

	switch {
	case syncErr != nil:
		return ExitSyncFailed
	case reportErr != nil:
		return ExitReportFailed
	}
	return ExitOK
}

// ---------------------------------------------------------------- reporting

func (a *Agent) credentialPath() string { return filepath.Join(a.Paths.StateDir, "machine-credential") }
func (a *Agent) noncePath() string      { return filepath.Join(a.Paths.StateDir, "enroll-nonce") }

// report enrolls (once, and only after a first successful sync) and then checks in. It is idempotent.
func (a *Agent) report(ctx context.Context, res SyncResult, syncErr error) error {
	rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	credBytes, err := readRegular(a.credentialPath(), 4096)
	cred := strings.TrimSpace(string(credBytes))
	if err != nil || cred == "" {
		if !a.loadState().FirstSyncOK {
			a.logf("not registering yet: waiting for a first successful key sync")
			return nil
		}
		if cred, err = a.enroll(rctx); err != nil {
			return err
		}
	}

	status, errText := "success", ""
	if syncErr != nil {
		status, errText = "error", syncErr.Error()
	}
	body := map[string]string{
		"agentVersion": a.Version,
		"result":       status,
		"error":        errText,
		"appliedEtag":  res.AppliedETag,
	}
	code, respBody, err := a.checkIn(rctx, cred, body)
	if err != nil {
		return err
	}
	if code == http.StatusUnauthorized {
		// The server no longer accepts this credential: an administrator removed the machine or replaced its
		// credential. Do not give up and do not retry blindly: ask to enroll. The server only agrees while an
		// administrator's explicit, single-use, time-limited "permit re-enrollment" is active (otherwise it answers
		// 409 and records the request, which is how the Machines page shows "re-enrollment requested").
		// The old credential file is only replaced once a new credential has really been issued.
		newCred, enrollErr := a.enroll(rctx)
		if enrollErr != nil {
			return fmt.Errorf("the server rejected this machine's credential and re-enrollment is not possible yet (an administrator must permit it): %w", enrollErr)
		}
		a.logf("re-enrolled under an administrator permit")
		if code, respBody, err = a.checkIn(rctx, newCred, body); err != nil {
			return err
		}
	}
	switch code {
	case http.StatusNoContent, http.StatusOK:
		_ = os.Remove(a.noncePath()) // the enrollment is confirmed; the nonce has done its job
		return nil
	case http.StatusUnauthorized:
		return errors.New("the server rejected the credential it has just issued")
	default:
		return fmt.Errorf("check-in answered HTTP %d: %s", code, clip(respBody))
	}
}

func (a *Agent) checkIn(ctx context.Context, cred string, body map[string]string) (int, []byte, error) {
	code, resp, err := a.postJSON(ctx, "/api/machines/checkin", cred, body)
	if err != nil {
		return 0, nil, fmt.Errorf("check-in: %w", err)
	}
	return code, resp, nil
}

// enroll obtains a machine credential. The nonce is persisted (fsync) BEFORE the request so that, if the
// response is lost, a retry proves it is the same requester and may be re-issued the credential.
func (a *Agent) enroll(ctx context.Context) (string, error) {
	tokenBytes, err := readRegular(a.Paths.EnrollTokenFile, 4096)
	token := strings.TrimSpace(string(tokenBytes))
	if err != nil || token == "" {
		return "", fmt.Errorf("no enrollment credential at %s", a.Paths.EnrollTokenFile)
	}
	fqdn, err := DetectFQDN(a.Config, a.Paths, a.Hostname)
	if err != nil {
		return "", err
	}
	nonce, err := a.loadOrCreateNonce()
	if err != nil {
		return "", err
	}

	code, body, err := a.postJSON(ctx, "/api/machines/enroll", token,
		map[string]string{"fqdn": fqdn, "nonce": nonce, "agentVersion": a.Version})
	if err != nil {
		return "", fmt.Errorf("enrollment: %w", err)
	}
	if code != http.StatusCreated {
		return "", fmt.Errorf("enrollment refused (HTTP %d): %s", code, clip(body))
	}
	cred := jsonField(body, "machineCredential")
	if !strings.HasPrefix(cred, "sbm_") {
		return "", errors.New("enrollment response did not contain a credential")
	}
	if err := WriteFileAtomic(a.credentialPath(), []byte(cred+"\n"), 0o600, a.Owner, 0o700); err != nil {
		return "", fmt.Errorf("saving machine credential: %w", err)
	}
	a.logf("enrolled as %s", fqdn)
	return cred, nil
}

func (a *Agent) loadOrCreateNonce() (string, error) {
	if b, err := readRegular(a.noncePath(), 256); err == nil {
		if n := strings.TrimSpace(string(b)); len(n) >= 22 {
			return n, nil
		}
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	if err := WriteFileAtomic(a.noncePath(), []byte(nonce+"\n"), 0o600, a.Owner, 0o700); err != nil {
		return "", fmt.Errorf("saving enrollment nonce: %w", err)
	}
	return nonce, nil
}

func (a *Agent) postJSON(ctx context.Context, path, bearer string, payload map[string]string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Config.BaseURL+path, strings.NewReader(toJSON(payload)))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("User-Agent", "ssh-buddy-agent/"+a.Version)
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	return resp.StatusCode, b, nil
}
