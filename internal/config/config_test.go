package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValidAndLoopback(t *testing.T) {
	c := Default()
	c.Dir = t.TempDir()
	c.resolvePaths()
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	if c.Network.HoneypotHost != "127.0.0.1" || c.Network.ManagementHost != "127.0.0.1" {
		t.Fatal("defaults must bind to loopback")
	}
	if got := c.HoneypotAddr(2222); got != "127.0.0.1:2222" {
		t.Fatalf("HoneypotAddr = %s", got)
	}
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("config.example.yaml: %v", err)
	}
	if c.FTP.PassiveHost != c.Network.HoneypotHost {
		t.Fatal("empty passive_host should default to the honeypot host")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	_, err := Load(write(t, "ssh:\n  prot: 2222\n"))
	if err == nil || !strings.Contains(err.Error(), "prot") {
		t.Fatalf("typo should be reported, got %v", err)
	}
}

func TestAllProblemsReported(t *testing.T) {
	_, err := Load(write(t, `
network:
  honeypot_host: not-an-ip
ssh:
  port: 8000
lab:
  source_ranges: ["nope"]
`))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"honeypot_host", "8000", "source_ranges"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestEnvOverridesFileAndBadEnvIsAnError(t *testing.T) {
	p := write(t, "sensor:\n  id: from-file\n")
	t.Setenv("HIVE_SENSOR_ID", "from-env")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sensor.ID != "from-env" {
		t.Fatalf("sensor id = %s, env should win", c.Sensor.ID)
	}
	t.Setenv("HIVE_API_PORT", "eighty")
	if _, err := Load(p); err == nil {
		t.Fatal("a non-numeric port in the environment must be an error")
	}
}

func TestRelativePathsResolveFromConfigDir(t *testing.T) {
	p := write(t, "paths:\n  data_dir: mydata\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Paths.DataDir != filepath.Join(filepath.Dir(p), "mydata") {
		t.Fatalf("data_dir = %s", c.Paths.DataDir)
	}
}

func TestPassiveRangeClashDetected(t *testing.T) {
	_, err := Load(write(t, "ftp:\n  passive_port_min: 2200\n  passive_port_max: 2300\n"))
	if err == nil {
		t.Fatal("passive range overlapping the SSH port should be rejected")
	}
}
