/*
©AngelaMos | 2026
Modified by Hiten, 2026: explicit bind addresses, local data paths,
validation, strict YAML parsing and reported environment errors.
Redis stream settings removed.

config.go

Configuration loading and validation.

Order of precedence: built-in defaults, then the YAML file, then
HIVE_* environment variables. Relative paths in the YAML file are
resolved against the directory that holds the file, so the binary
behaves the same no matter where it is started from.
*/

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Sensor    SensorConfig    `yaml:"sensor"`
	Network   NetworkConfig   `yaml:"network"`
	Paths     PathsConfig     `yaml:"paths"`
	Limits    LimitsConfig    `yaml:"limits"`
	SSH       SSHConfig       `yaml:"ssh"`
	HTTP      HTTPConfig      `yaml:"http"`
	FTP       FTPConfig       `yaml:"ftp"`
	SMB       SMBConfig       `yaml:"smb"`
	MySQL     MySQLConfig     `yaml:"mysql"`
	Redis     RedisConfig     `yaml:"redis"`
	Database  DatabaseConfig  `yaml:"database"`
	Pipeline  PipelineConfig  `yaml:"pipeline"`
	Detection DetectionConfig `yaml:"detection"`
	Cases     CasesConfig     `yaml:"cases"`
	Response  ResponseConfig  `yaml:"response"`
	Lab       LabConfig       `yaml:"lab"`
	API       APIConfig       `yaml:"api"`
	GeoIP     GeoIPConfig     `yaml:"geoip"`
	Log       LogConfig       `yaml:"log"`

	// Dir is the directory relative paths are resolved against.
	Dir string `yaml:"-"`
	// Source records where the configuration came from.
	Source string `yaml:"-"`
}

type SensorConfig struct {
	ID       string `yaml:"id"`
	Hostname string `yaml:"hostname"`
	Region   string `yaml:"region"`
}

// NetworkConfig keeps the dashboard and the decoys on separate
// addresses. Both default to loopback.
type NetworkConfig struct {
	ManagementHost string `yaml:"management_host"`
	HoneypotHost   string `yaml:"honeypot_host"`
}

type PathsConfig struct {
	DataDir    string `yaml:"data_dir"`
	HostKeys   string `yaml:"host_keys"`
	Replays    string `yaml:"replays"`
	Uploads    string `yaml:"uploads"`
	Exports    string `yaml:"exports"`
	LabRuns    string `yaml:"lab_runs"`
	Migrations string `yaml:"migrations"`
	Frontend   string `yaml:"frontend"`
}

type LimitsConfig struct {
	MaxConnectionsPerService int           `yaml:"max_connections_per_service"`
	IdleTimeout              time.Duration `yaml:"idle_timeout"`
	MaxSessionDuration       time.Duration `yaml:"max_session_duration"`
	MaxLineBytes             int           `yaml:"max_line_bytes"`
	MaxUploadBytes           int64         `yaml:"max_upload_bytes"`
	MaxHTTPBodyBytes         int64         `yaml:"max_http_body_bytes"`
	// Per-address connection rate for each decoy. Connections over
	// the rate are closed without an event.
	ConnectionRatePerIP  float64 `yaml:"connection_rate_per_ip"`
	ConnectionBurstPerIP int     `yaml:"connection_burst_per_ip"`
}

type TestCredential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type SSHConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Port        int    `yaml:"port"`
	Banner      string `yaml:"banner"`
	HostKeyPath string `yaml:"host_key_path"`
	Hostname    string `yaml:"hostname"`
	// AuthMode is "accept-all" (default decoy behaviour) or
	// "test-credentials", which only accepts TestCredentials so
	// failed-login scenarios can be exercised.
	AuthMode        string           `yaml:"auth_mode"`
	TestCredentials []TestCredential `yaml:"test_credentials"`
}

type HTTPConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Port         int    `yaml:"port"`
	ServerHeader string `yaml:"server_header"`
}

type FTPConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Banner  string `yaml:"banner"`
	// PassiveHost is the address put in the 227 reply. Empty means
	// the honeypot bind address.
	PassiveHost    string `yaml:"passive_host"`
	PassivePortMin int    `yaml:"passive_port_min"`
	PassivePortMax int    `yaml:"passive_port_max"`
}

type SMBConfig struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

type MySQLConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Port          int    `yaml:"port"`
	ServerVersion string `yaml:"server_version"`
}

type RedisConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Port          int    `yaml:"port"`
	ServerVersion string `yaml:"server_version"`
}

type DatabaseConfig struct {
	DSN         string        `yaml:"dsn"`
	PoolMin     int           `yaml:"pool_min"`
	PoolMax     int           `yaml:"pool_max"`
	ConnTimeout time.Duration `yaml:"conn_timeout"`
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

type PipelineConfig struct {
	QueueSize     int           `yaml:"queue_size"`
	EnqueueWait   time.Duration `yaml:"enqueue_wait"`
	PersistRetry  int           `yaml:"persist_retry"`
	DrainTimeout  time.Duration `yaml:"drain_timeout"`
	LiveBuffer    int           `yaml:"live_buffer"`
	ShutdownGrace time.Duration `yaml:"shutdown_grace"`
}

type DetectionConfig struct {
	RulesFile string `yaml:"rules_file"`
}

type CasesConfig struct {
	CorrelationWindow time.Duration `yaml:"correlation_window"`
	AnalystName       string        `yaml:"analyst_name"`
}

type ResponseConfig struct {
	Enabled bool `yaml:"enabled"`
	// MinSeverity is the lowest case severity that creates a
	// pending restriction request.
	MinSeverity   string        `yaml:"min_severity"`
	DefaultExpiry time.Duration `yaml:"default_expiry"`
}

// LabConfig marks which source addresses are the analyst's own test
// traffic. Events from these ranges get origin "lab" so they can be
// filtered and reported separately from anything else.
type LabConfig struct {
	SourceRanges []string `yaml:"source_ranges"`
	ScenariosDir string   `yaml:"scenarios_dir"`
}

// LabPrefixes parses Lab.SourceRanges. Validate reports bad values.
func (c *Config) LabPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range c.Lab.SourceRanges {
		if p, err := netip.ParsePrefix(r); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

type APIConfig struct {
	Port         int           `yaml:"port"`
	CORSOrigins  []string      `yaml:"cors_origins"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	// ServeFrontend serves the built dashboard from Paths.Frontend.
	ServeFrontend bool `yaml:"serve_frontend"`
}

type GeoIPConfig struct {
	DBPath string `yaml:"db_path"`
}

type LogConfig struct {
	Level      string `yaml:"level"`
	JSONFormat bool   `yaml:"json_format"`
}

func Default() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = DefaultHostname
	}

	return &Config{
		Sensor: SensorConfig{
			ID:       "hive-01",
			Hostname: hostname,
			Region:   "local",
		},
		Network: NetworkConfig{
			ManagementHost: "127.0.0.1",
			HoneypotHost:   "127.0.0.1",
		},
		Paths: PathsConfig{
			DataDir:    "data",
			HostKeys:   "data/hostkeys",
			Replays:    "data/replays",
			Uploads:    "data/uploads",
			Exports:    "data/exports",
			LabRuns:    "data/lab-runs",
			Migrations: "migrations",
			Frontend:   "frontend/dist",
		},
		Limits: LimitsConfig{
			MaxConnectionsPerService: 64,
			IdleTimeout:              5 * time.Minute,
			MaxSessionDuration:       DefaultSessionTimeout,
			MaxLineBytes:             8192,
			MaxUploadBytes:           DefaultMaxUploadSize,
			MaxHTTPBodyBytes:         64 * 1024,
			ConnectionRatePerIP:      20,
			ConnectionBurstPerIP:     50,
		},
		SSH: SSHConfig{
			Enabled:  true,
			Port:     DefaultSSHPort,
			Banner:   SSHBanner,
			Hostname: DefaultHostname,
			AuthMode: SSHAuthAcceptAll,
		},
		HTTP: HTTPConfig{
			Enabled:      true,
			Port:         DefaultHTTPPort,
			ServerHeader: HTTPServer,
		},
		FTP: FTPConfig{
			Enabled:        true,
			Port:           DefaultFTPPort,
			Banner:         FTPBanner,
			PassivePortMin: 30000,
			PassivePortMax: 30009,
		},
		SMB: SMBConfig{
			Enabled: true,
			Port:    DefaultSMBPort,
		},
		MySQL: MySQLConfig{
			Enabled:       true,
			Port:          DefaultMySQLPort,
			ServerVersion: MySQLBanner,
		},
		Redis: RedisConfig{
			Enabled:       true,
			Port:          DefaultRedisPort,
			ServerVersion: RedisBanner,
		},
		Database: DatabaseConfig{
			DSN:         "postgres://hive:hive@127.0.0.1:5432/hive?sslmode=disable",
			PoolMin:     DefaultDBPoolMin,
			PoolMax:     DefaultDBPoolMax,
			ConnTimeout: DefaultDBTimeout,
			IdleTimeout: DefaultDBIdleTimeout,
		},
		Pipeline: PipelineConfig{
			QueueSize:     DefaultEventBusBuffer,
			EnqueueWait:   250 * time.Millisecond,
			PersistRetry:  3,
			DrainTimeout:  10 * time.Second,
			LiveBuffer:    256,
			ShutdownGrace: DefaultShutdownTimeout,
		},
		Detection: DetectionConfig{
			RulesFile: "",
		},
		Cases: CasesConfig{
			CorrelationWindow: 30 * time.Minute,
			AnalystName:       "analyst",
		},
		Response: ResponseConfig{
			Enabled:       true,
			MinSeverity:   "high",
			DefaultExpiry: time.Hour,
		},
		Lab: LabConfig{
			SourceRanges: []string{"127.0.0.0/8", "::1/128"},
			ScenariosDir: "scenarios",
		},
		API: APIConfig{
			Port: DefaultAPIPort,
			CORSOrigins: []string{
				"http://127.0.0.1:5173",
				"http://localhost:5173",
			},
			ReadTimeout:   DefaultReadTimeout,
			WriteTimeout:  DefaultWriteTimeout,
			ServeFrontend: true,
		},
		GeoIP: GeoIPConfig{
			DBPath: "",
		},
		Log: LogConfig{
			Level:      "info",
			JSONFormat: false,
		},
		Dir:    ".",
		Source: "defaults",
	}
}

// Load reads the YAML file at path (if it exists), applies
// environment overrides, resolves paths and validates the result.
// A missing file is allowed so the binary can run on defaults;
// the Source field says which happened.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if decErr := dec.Decode(cfg); decErr != nil &&
			!errors.Is(decErr, io.EOF) {
			return nil, fmt.Errorf(
				"parsing config %s: %w", path, decErr,
			)
		}
		abs, absErr := filepath.Abs(path)
		if absErr != nil {
			return nil, fmt.Errorf("resolving %s: %w", path, absErr)
		}
		cfg.Dir = filepath.Dir(abs)
		cfg.Source = abs
	case os.IsNotExist(err):
		wd, _ := os.Getwd()
		cfg.Dir = wd
		cfg.Source = "defaults (no file at " + path + ")"
	default:
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}

	cfg.resolvePaths()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) resolvePaths() {
	resolve := func(p *string) {
		if *p == "" || filepath.IsAbs(*p) {
			return
		}
		*p = filepath.Join(c.Dir, *p)
	}
	resolve(&c.Paths.DataDir)
	resolve(&c.Paths.HostKeys)
	resolve(&c.Paths.Replays)
	resolve(&c.Paths.Uploads)
	resolve(&c.Paths.Exports)
	resolve(&c.Paths.LabRuns)
	resolve(&c.Lab.ScenariosDir)
	resolve(&c.Paths.Migrations)
	resolve(&c.Paths.Frontend)
	resolve(&c.Detection.RulesFile)
	resolve(&c.GeoIP.DBPath)
	if c.FTP.PassiveHost == "" {
		c.FTP.PassiveHost = c.Network.HoneypotHost
	}
	if c.SSH.HostKeyPath == "" {
		c.SSH.HostKeyPath = filepath.Join(
			c.Paths.HostKeys, "ssh_host_ed25519",
		)
	}
	resolve(&c.SSH.HostKeyPath)
}

// ServicePort pairs a service name with its configured port.
type ServicePort struct {
	Name    string
	Host    string
	Port    int
	Enabled bool
}

// Listeners returns every listener the application will open,
// including the FTP passive range endpoints.
func (c *Config) Listeners() []ServicePort {
	return []ServicePort{
		{"api", c.Network.ManagementHost, c.API.Port, true},
		{"ssh", c.Network.HoneypotHost, c.SSH.Port, c.SSH.Enabled},
		{"http", c.Network.HoneypotHost, c.HTTP.Port, c.HTTP.Enabled},
		{"ftp", c.Network.HoneypotHost, c.FTP.Port, c.FTP.Enabled},
		{"smb", c.Network.HoneypotHost, c.SMB.Port, c.SMB.Enabled},
		{"mysql", c.Network.HoneypotHost, c.MySQL.Port, c.MySQL.Enabled},
		{"redis", c.Network.HoneypotHost, c.Redis.Port, c.Redis.Enabled},
	}
}

// Validate checks ports, addresses and values that would otherwise
// fail later with a less helpful message.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if c.Limits.ConnectionRatePerIP <= 0 || c.Limits.ConnectionBurstPerIP < 1 {
		add("limits.connection_rate_per_ip and limits.connection_burst_per_ip must be positive")
	}
	if c.Limits.ConnectionRatePerIP <= 0 || c.Limits.ConnectionBurstPerIP < 1 {
		add("limits.connection_rate_per_ip and limits.connection_burst_per_ip must be positive")
	}
	for _, r := range c.Lab.SourceRanges {
		if _, err := netip.ParsePrefix(r); err != nil {
			add("lab.source_ranges entry %q is not a CIDR range", r)
		}
	}

	for _, h := range []struct{ name, value string }{
		{"network.management_host", c.Network.ManagementHost},
		{"network.honeypot_host", c.Network.HoneypotHost},
	} {
		if _, err := netip.ParseAddr(h.value); err != nil {
			add("%s %q is not an IP address", h.name, h.value)
		}
	}

	seen := map[string]string{}
	for _, l := range c.Listeners() {
		if !l.Enabled {
			continue
		}
		if l.Port < 1 || l.Port > 65535 {
			add("%s port %d is outside 1-65535", l.Name, l.Port)
			continue
		}
		// Ports are compared without the host. Running two services
		// on one port with different hosts is possible but confusing
		// in a lab, so it is rejected.
		if other, dup := seen[strconv.Itoa(l.Port)]; dup {
			add("%s and %s both use port %d", other, l.Name, l.Port)
		}
		seen[strconv.Itoa(l.Port)] = l.Name
	}

	if c.FTP.Enabled {
		lo, hi := c.FTP.PassivePortMin, c.FTP.PassivePortMax
		switch {
		case lo < 1024 || hi > 65535 || lo > hi:
			add("ftp passive range %d-%d is invalid (use 1024-65535, min <= max)", lo, hi)
		default:
			for p := lo; p <= hi; p++ {
				if other, clash := seen[strconv.Itoa(p)]; clash {
					add("ftp passive port %d clashes with %s", p, other)
				}
			}
		}
		if c.FTP.PassiveHost != "" {
			if _, err := netip.ParseAddr(c.FTP.PassiveHost); err != nil {
				add("ftp.passive_host %q is not an IP address", c.FTP.PassiveHost)
			}
		}
	}

	switch c.SSH.AuthMode {
	case SSHAuthAcceptAll:
	case SSHAuthTestCredentials:
		if len(c.SSH.TestCredentials) == 0 {
			add("ssh.auth_mode is test-credentials but ssh.test_credentials is empty")
		}
	default:
		add("ssh.auth_mode %q must be %q or %q",
			c.SSH.AuthMode, SSHAuthAcceptAll, SSHAuthTestCredentials)
	}

	if c.Limits.MaxConnectionsPerService < 1 {
		add("limits.max_connections_per_service must be at least 1")
	}
	if c.Limits.IdleTimeout <= 0 || c.Limits.MaxSessionDuration <= 0 {
		add("limits.idle_timeout and limits.max_session_duration must be positive")
	}
	if c.Limits.MaxLineBytes < 256 {
		add("limits.max_line_bytes must be at least 256")
	}
	if c.Limits.MaxUploadBytes < 1 || c.Limits.MaxHTTPBodyBytes < 1 {
		add("limits.max_upload_bytes and limits.max_http_body_bytes must be positive")
	}
	if c.Pipeline.QueueSize < 1 {
		add("pipeline.queue_size must be at least 1")
	}
	if c.Pipeline.LiveBuffer < 1 {
		add("pipeline.live_buffer must be at least 1")
	}
	if c.Cases.CorrelationWindow <= 0 {
		add("cases.correlation_window must be positive")
	}
	if _, ok := SeverityRank[c.Response.MinSeverity]; !ok {
		add("response.min_severity %q must be one of low, medium, high, critical",
			c.Response.MinSeverity)
	}
	if c.Database.DSN == "" {
		add("database.dsn is empty")
	}
	if c.Sensor.ID == "" {
		add("sensor.id is empty")
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level %q must be debug, info, warn or error", c.Log.Level)
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
	return nil
}

// Addr joins a host and port. IPv6 hosts are bracketed.
func Addr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// HoneypotAddr is the listen address for a decoy service.
func (c *Config) HoneypotAddr(port int) string {
	return Addr(c.Network.HoneypotHost, port)
}

// ManagementAddr is the listen address for the API and dashboard.
func (c *Config) ManagementAddr() string {
	return Addr(c.Network.ManagementHost, c.API.Port)
}

func applyEnvOverrides(cfg *Config) error {
	var errs []string

	str := func(key string, target *string) {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			*target = v
		}
	}
	port := func(key string, target *int) {
		v, ok := os.LookupEnv(key)
		if !ok || v == "" {
			return
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Sprintf("%s=%q is not a port number", key, v))
			return
		}
		*target = n
	}
	boolean := func(key string, target *bool) {
		v, ok := os.LookupEnv(key)
		if !ok || v == "" {
			return
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s=%q is not true/false", key, v))
			return
		}
		*target = b
	}

	str("HIVE_SENSOR_ID", &cfg.Sensor.ID)
	str("HIVE_SENSOR_REGION", &cfg.Sensor.Region)
	str("HIVE_DATABASE_URL", &cfg.Database.DSN)
	str("HIVE_GEOIP_DB_PATH", &cfg.GeoIP.DBPath)
	str("HIVE_LOG_LEVEL", &cfg.Log.Level)
	str("HIVE_DATA_DIR", &cfg.Paths.DataDir)
	str("HIVE_MANAGEMENT_HOST", &cfg.Network.ManagementHost)
	str("HIVE_HONEYPOT_HOST", &cfg.Network.HoneypotHost)
	if v, ok := os.LookupEnv("HIVE_CORS_ORIGINS"); ok && v != "" {
		cfg.API.CORSOrigins = strings.Split(v, ",")
	}

	port("HIVE_API_PORT", &cfg.API.Port)
	port("HIVE_SSH_PORT", &cfg.SSH.Port)
	port("HIVE_HTTP_PORT", &cfg.HTTP.Port)
	port("HIVE_FTP_PORT", &cfg.FTP.Port)
	port("HIVE_SMB_PORT", &cfg.SMB.Port)
	port("HIVE_MYSQL_PORT", &cfg.MySQL.Port)
	port("HIVE_REDIS_PORT", &cfg.Redis.Port)

	boolean("HIVE_SSH_ENABLED", &cfg.SSH.Enabled)
	boolean("HIVE_HTTP_ENABLED", &cfg.HTTP.Enabled)
	boolean("HIVE_FTP_ENABLED", &cfg.FTP.Enabled)
	boolean("HIVE_SMB_ENABLED", &cfg.SMB.Enabled)
	boolean("HIVE_MYSQL_ENABLED", &cfg.MySQL.Enabled)
	boolean("HIVE_REDIS_ENABLED", &cfg.Redis.Enabled)

	if len(errs) > 0 {
		return fmt.Errorf("environment overrides:\n  - %s",
			strings.Join(errs, "\n  - "))
	}
	return nil
}

// EnvKeys lists every variable applyEnvOverrides reads. The doctor
// command and the docs use it so the list cannot drift.
func EnvKeys() []string {
	return []string{
		"HIVE_SENSOR_ID", "HIVE_SENSOR_REGION", "HIVE_DATABASE_URL",
		"HIVE_GEOIP_DB_PATH", "HIVE_LOG_LEVEL", "HIVE_DATA_DIR",
		"HIVE_MANAGEMENT_HOST", "HIVE_HONEYPOT_HOST", "HIVE_CORS_ORIGINS",
		"HIVE_API_PORT", "HIVE_SSH_PORT", "HIVE_HTTP_PORT",
		"HIVE_FTP_PORT", "HIVE_SMB_PORT", "HIVE_MYSQL_PORT",
		"HIVE_REDIS_PORT", "HIVE_SSH_ENABLED", "HIVE_HTTP_ENABLED",
		"HIVE_FTP_ENABLED", "HIVE_SMB_ENABLED", "HIVE_MYSQL_ENABLED",
		"HIVE_REDIS_ENABLED",
	}
}
