package agent

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// DetectFQDN derives the machine's fully qualified name without relying on DNS (DNS registration is done
// from the server later, so it cannot be a prerequisite). Order:
//  1. the fqdn setting in agent.conf
//  2. the kernel hostname, if it already contains a dot
//  3. a dotted name for that host in /etc/hosts
//  4. the hostname plus the first search/domain entry of /etc/resolv.conf
func DetectFQDN(cfg Config, p Paths, hostname func() (string, error)) (string, error) {
	if cfg.FQDN != "" {
		return normalizeFQDN(cfg.FQDN)
	}
	host, err := hostname()
	if err != nil || host == "" {
		return "", errors.New("cannot read the hostname; set fqdn= in " + p.ConfigFile)
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if strings.Contains(host, ".") {
		return normalizeFQDN(host)
	}
	short := host

	if name := fqdnFromHosts(p.HostsFile, short); name != "" {
		return normalizeFQDN(name)
	}
	if domain := searchDomain(p.ResolvConf); domain != "" {
		return normalizeFQDN(short + "." + domain)
	}
	return "", fmt.Errorf("cannot determine a fully qualified name for %q: no dotted name in %s and no search/domain in %s; set fqdn= in %s",
		short, p.HostsFile, p.ResolvConf, p.ConfigFile)
}

func fqdnFromHosts(path, short string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, name := range fields[1:] {
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			first, _, dotted := strings.Cut(name, ".")
			if dotted && first == short && !strings.HasPrefix(name, "localhost.") {
				return name
			}
		}
	}
	return ""
}

func searchDomain(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
			return strings.ToLower(strings.TrimSuffix(fields[1], "."))
		}
	}
	return ""
}

// normalizeFQDN applies the same canonical form as the server (which stays authoritative): lower case, one
// trailing dot removed, at least two labels of letters/digits/hyphen, no all-numeric last label. Non-ASCII
// names are rejected rather than converted; Linux hostnames are ASCII.
func normalizeFQDN(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) == 0 || len(s) > 253 {
		return "", errors.New("invalid hostname length")
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q is not fully qualified", s)
	}
	allDigits := true
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("%q has an invalid label", s)
		}
		allDigits = true
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c == '-':
				allDigits = false
			case c >= '0' && c <= '9':
			default:
				return "", fmt.Errorf("%q contains an invalid character", s)
			}
		}
	}
	if allDigits {
		return "", fmt.Errorf("%q looks like an IP address", s)
	}
	return s, nil
}
