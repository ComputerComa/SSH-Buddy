package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConf(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "agent.conf")
	must(t, os.WriteFile(p, []byte(content), 0o644))
	return p
}

func TestLoadConfig(t *testing.T) {
	c, err := LoadConfig(writeConf(t, "# comment\nurl = https://keys.example.com/\ninterval=10m\nfqdn=Web1.Example.Com.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://keys.example.com" || c.Interval != 10*time.Minute || c.FQDN != "Web1.Example.Com." {
		t.Errorf("%+v", c)
	}
	d, err := LoadConfig(writeConf(t, "url=https://keys.example.com\n"))
	if err != nil || d.Interval != DefaultInterval {
		t.Errorf("default interval = %v, %v", d.Interval, err)
	}
	h, err := LoadConfig(writeConf(t, "url=HTTP://keys.example.com:8080/\n"))
	if err != nil || h.BaseURL != "http://keys.example.com:8080" {
		t.Errorf("plain http origin = %q, %v", h.BaseURL, err)
	}
}

func TestLoadConfigRejectsBadInput(t *testing.T) {
	for name, content := range map[string]string{
		"other scheme":   "url=ftp://keys.example.com\n",
		"no scheme":      "url=keys.example.com\n",
		"http with path": "url=http://keys.example.com/api\n",
		"no url":         "interval=5m\n",
		"url with path":  "url=https://keys.example.com/api\n",
		"userinfo":       "url=https://u:p@keys.example.com\n",
		"query":          "url=https://keys.example.com/?x=1\n",
		"short interval": "url=https://k.example.com\ninterval=5s\n",
		"huge interval":  "url=https://k.example.com\ninterval=720h\n",
		"bad interval":   "url=https://k.example.com\ninterval=often\n",
		"unknown key":    "url=https://k.example.com\ninsecure=true\n",
		"not key value":  "url\n",
	} {
		if _, err := LoadConfig(writeConf(t, content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func fqdnEnv(t *testing.T, hosts, resolv string) (Config, Paths) {
	dir := t.TempDir()
	p := Paths{ConfigFile: "/etc/ssh-buddy/agent.conf", HostsFile: filepath.Join(dir, "hosts"), ResolvConf: filepath.Join(dir, "resolv.conf")}
	if hosts != "" {
		must(t, os.WriteFile(p.HostsFile, []byte(hosts), 0o644))
	}
	if resolv != "" {
		must(t, os.WriteFile(p.ResolvConf, []byte(resolv), 0o644))
	}
	return Config{}, p
}

func TestDetectFQDN(t *testing.T) {
	host := func(h string) func() (string, error) { return func() (string, error) { return h, nil } }

	t.Run("config override wins", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "", "")
		cfg.FQDN = "Override.Example.COM."
		got, err := DetectFQDN(cfg, p, host("ignored"))
		if err != nil || got != "override.example.com" {
			t.Errorf("%q %v", got, err)
		}
	})
	t.Run("dotted hostname", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "", "")
		got, err := DetectFQDN(cfg, p, host("Web1.Home.Example"))
		if err != nil || got != "web1.home.example" {
			t.Errorf("%q %v", got, err)
		}
	})
	t.Run("from /etc/hosts", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "127.0.0.1 localhost localhost.localdomain\n127.0.1.1 web1.lab.example web1  # proxmox\n", "search other.example\n")
		got, err := DetectFQDN(cfg, p, host("web1"))
		if err != nil || got != "web1.lab.example" {
			t.Errorf("%q %v", got, err)
		}
	})
	t.Run("from resolv.conf search", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "127.0.0.1 localhost\n", "nameserver 10.0.0.1\nsearch lab.example home.example\n")
		got, err := DetectFQDN(cfg, p, host("web1"))
		if err != nil || got != "web1.lab.example" {
			t.Errorf("%q %v", got, err)
		}
	})
	t.Run("domain directive", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "", "domain lab.example\n")
		got, err := DetectFQDN(cfg, p, host("web1"))
		if err != nil || got != "web1.lab.example" {
			t.Errorf("%q %v", got, err)
		}
	})
	t.Run("fails clearly", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "127.0.0.1 localhost\n", "nameserver 10.0.0.1\n")
		_, err := DetectFQDN(cfg, p, host("web1"))
		if err == nil || !strings.Contains(err.Error(), "fqdn=") {
			t.Errorf("%v", err)
		}
	})
	t.Run("hostname error", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "", "")
		if _, err := DetectFQDN(cfg, p, func() (string, error) { return "", errors.New("boom") }); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("invalid names are rejected", func(t *testing.T) {
		cfg, p := fqdnEnv(t, "", "")
		for _, bad := range []string{"web_1.example.com", "10.0.0.5", "-a.example.com", "a..example.com", "ünï.example.com"} {
			cfg.FQDN = bad
			if got, err := DetectFQDN(cfg, p, host("x")); err == nil {
				t.Errorf("%q accepted as %q", bad, got)
			}
		}
	})
}
