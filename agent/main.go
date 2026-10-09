// ssh-buddy-agent keeps /etc/ssh/authorized_keys.d/root-managed in sync with an SSH Buddy server and
// reports the machine's status back.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/ssh-buddy/agent/internal/agent"
	"github.com/ssh-buddy/agent/internal/install"
)

// version is stamped by agent/build.sh (-ldflags "-X main.version=...").
var version = "dev"

const usage = `usage: ssh-buddy-agent <command> [--config FILE]

commands:
  sync      synchronize the key list, then report status (run by the systemd timer)
  install   write the sshd drop-in and systemd units (transactional; run as root)
  version   print the version
`

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return agent.ExitUsage
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Printf("ssh-buddy-agent %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	case "sync", "install":
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", cmd, usage)
		return agent.ExitUsage
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	paths := agent.DefaultPaths()
	fs.StringVar(&paths.ConfigFile, "config", paths.ConfigFile, "path to agent.conf")
	if err := fs.Parse(rest); err != nil {
		return agent.ExitUsage
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "ssh-buddy-agent: must run as root")
		return agent.ExitUsage
	}
	cfg, err := agent.LoadConfig(paths.ConfigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-buddy-agent: %v\n", err)
		return agent.ExitUsage
	}

	if cmd == "install" {
		if err := install.Defaults(cfg, paths).Install(); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-buddy-agent: install failed: %v\n", err)
			return 1
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.New(cfg, paths, version).Run(ctx)
}
