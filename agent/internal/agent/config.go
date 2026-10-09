// Package agent implements key synchronization, enrollment and status reporting.
package agent

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Paths locates everything the agent reads or writes. Tests point these at a temp directory.
type Paths struct {
	ConfigFile      string
	EnrollTokenFile string
	StateDir        string
	ManagedFile     string
	LockFile        string
	HostsFile       string
	ResolvConf      string
}

// DefaultPaths are the production locations.
func DefaultPaths() Paths {
	return Paths{
		ConfigFile:      "/etc/ssh-buddy/agent.conf",
		EnrollTokenFile: "/etc/ssh-buddy/enroll-token",
		StateDir:        "/var/lib/ssh-buddy-agent",
		ManagedFile:     "/etc/ssh/authorized_keys.d/root-managed",
		LockFile:        "/run/ssh-buddy-agent.lock",
		HostsFile:       "/etc/hosts",
		ResolvConf:      "/etc/resolv.conf",
	}
}

// Config is the content of agent.conf.
type Config struct {
	// BaseURL is the SSH Buddy origin, e.g. https://keys.example.com (no path).
	BaseURL string
	// Interval is how often the timer runs the agent.
	Interval time.Duration
	// FQDN overrides hostname detection when set.
	FQDN string
}

const (
	DefaultInterval = 5 * time.Minute
	MinInterval     = time.Minute
	MaxInterval     = 24 * time.Hour
)

// LoadConfig reads simple key=value lines ('#' comments allowed).
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	defer f.Close()

	cfg := Config{Interval: DefaultInterval}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("%s:%d: expected key=value", path, n)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "url":
			cfg.BaseURL = val
		case "interval":
			d, err := time.ParseDuration(val)
			if err != nil {
				return Config{}, fmt.Errorf("%s:%d: bad interval: %v", path, n, err)
			}
			cfg.Interval = d
		case "fqdn":
			cfg.FQDN = val
		default:
			return Config{}, fmt.Errorf("%s:%d: unknown setting %q", path, n, key)
		}
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}

// Validate checks the settings. The URL must be https: the agent never talks plain HTTP.
func (c *Config) Validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || c.BaseURL == "" {
		return errors.New("url is required (for example url=https://keys.example.com)")
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("url must be an https:// address")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("url must be just the origin, such as https://keys.example.com")
	}
	c.BaseURL = "https://" + u.Host
	if c.Interval < MinInterval || c.Interval > MaxInterval {
		return fmt.Errorf("interval must be between %s and %s", MinInterval, MaxInterval)
	}
	return nil
}
