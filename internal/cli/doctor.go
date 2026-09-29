/*
Hiten | 2026
doctor.go

`hive doctor` checks the local setup and says how to fix each
problem. It does not change anything. Exit status is 1 when any
check fails.
*/

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/detection"
	"github.com/CarterPerez-dev/hive/internal/store"
)

type doctorResult struct {
	status string // ok, warn, fail
	name   string
	detail string
	fix    string
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check configuration, database, ports and files",
		RunE: func(cmd *cobra.Command, _ []string) error {
			results := runDoctor(cmd.Context())
			failed := 0
			for _, r := range results {
				mark := map[string]string{"ok": " OK ", "warn": "WARN", "fail": "FAIL"}[r.status]
				fmt.Printf("[%s] %-22s %s\n", mark, r.name, r.detail)
				if r.fix != "" && r.status != "ok" {
					fmt.Printf("       %-22s fix: %s\n", "", r.fix)
				}
				if r.status == "fail" {
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d check(s) failed", failed)
			}
			fmt.Println("\nAll required checks passed.")
			return nil
		},
	}
}

func runDoctor(ctx context.Context) []doctorResult {
	var out []doctorResult
	add := func(status, name, detail, fix string) {
		out = append(out, doctorResult{status, name, detail, fix})
	}

	cfg, err := loadConfig()
	if err != nil {
		add("fail", "config", err.Error(), "copy config.example.yaml to config.yaml and fix the listed values")
		return out
	}
	add("ok", "config", cfg.Source, "")

	if a, _ := netip.ParseAddr(cfg.Network.HoneypotHost); !a.IsLoopback() {
		add("warn", "decoy bind address", cfg.Network.HoneypotHost+" is not loopback",
			"other machines on the network may reach the decoys; use 127.0.0.1 unless you mean it")
	} else {
		add("ok", "decoy bind address", cfg.Network.HoneypotHost, "")
	}
	if a, _ := netip.ParseAddr(cfg.Network.ManagementHost); !a.IsLoopback() {
		add("warn", "dashboard address", cfg.Network.ManagementHost+" is not loopback",
			"the dashboard has no login; keep it on 127.0.0.1")
	}

	for _, d := range []string{cfg.Paths.DataDir, cfg.Paths.HostKeys, cfg.Paths.Replays,
		cfg.Paths.Uploads, cfg.Paths.Exports, cfg.Paths.LabRuns} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			add("fail", "directory", d+": "+err.Error(), "check permissions on the data directory")
			continue
		}
		probe := filepath.Join(d, ".doctor")
		if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
			add("fail", "directory", d+" is not writable", "check permissions on the data directory")
			continue
		}
		_ = os.Remove(probe)
	}
	add("ok", "data directories", cfg.Paths.DataDir, "")

	if _, err := os.Stat(filepath.Join(cfg.Paths.Migrations, "001_extensions.sql")); err != nil {
		add("fail", "migrations", "no migrations at "+cfg.Paths.Migrations, "set paths.migrations to the repository's migrations directory")
	}

	rs, src, err := detection.LoadRules(cfg.Detection.RulesFile)
	if err != nil {
		add("fail", "rules", err.Error(), "fix the rule file or remove detection.rules_file to use the defaults")
	} else {
		add("ok", "rules", fmt.Sprintf("%d rules from %s", len(rs), src), "")
	}

	if cfg.GeoIP.DBPath != "" {
		if _, err := os.Stat(cfg.GeoIP.DBPath); err != nil {
			add("warn", "geoip", "configured file missing: "+cfg.GeoIP.DBPath, "download a GeoLite2-City database or clear geoip.db_path")
		} else {
			add("ok", "geoip", cfg.GeoIP.DBPath, "")
		}
	} else {
		add("ok", "geoip", "off (optional)", "")
	}

	if _, err := os.Stat(filepath.Join(cfg.Paths.Frontend, "index.html")); err != nil {
		add("warn", "dashboard build", "no built dashboard at "+cfg.Paths.Frontend, "run scripts/build-local.sh, or use scripts/dev.sh for the dev server")
	} else {
		add("ok", "dashboard build", cfg.Paths.Frontend, "")
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pg, err := store.NewPgxStore(dctx, cfg.Database)
	if err != nil {
		add("fail", "postgresql", err.Error(), "start PostgreSQL and check database.dsn (scripts/setup-local.sh creates the role and database)")
	} else {
		defer pg.Close()
		add("ok", "postgresql", redactDSN(cfg.Database.DSN), "")
		v, err := pg.SchemaVersion(dctx)
		switch {
		case err != nil:
			add("fail", "schema", "cannot read migration table: "+err.Error(), "run `hive migrate up`")
		case v < config.RequiredMigration:
			add("fail", "schema", fmt.Sprintf("migration %d, need %d", v, config.RequiredMigration), "run `hive migrate up`")
		default:
			add("ok", "schema", fmt.Sprintf("migration %d", v), "")
		}
	}

	running := labRunning(cfg)
	for _, l := range cfg.Listeners() {
		if !l.Enabled {
			continue
		}
		host := cfg.Network.HoneypotHost
		if l.Name == "api" {
			host = cfg.Network.ManagementHost
		}
		addr := config.Addr(host, l.Port)
		ln, err := net.Listen("tcp", addr)
		switch {
		case err == nil:
			_ = ln.Close()
			add("ok", "port "+l.Name, addr+" is free", "")
		case running:
			add("ok", "port "+l.Name, addr+" in use (the lab is running)", "")
		case errors.Is(err, syscall.EADDRINUSE):
			add("fail", "port "+l.Name, addr+" is used by another program",
				fmt.Sprintf("stop that program or change %s port in config.yaml (see `ss -ltnp 'sport = :%d'`)", l.Name, l.Port))
		default:
			add("fail", "port "+l.Name, err.Error(), "check network settings in config.yaml")
		}
	}
	return out
}

// labRunning checks whether this lab's API answers on its address.
func labRunning(cfg *config.Config) bool {
	c := http.Client{Timeout: time.Second}
	resp, err := c.Get("http://" + cfg.ManagementAddr() + "/api/health")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
