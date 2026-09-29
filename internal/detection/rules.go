/*
Hiten | 2026
rules.go

Rule definitions and validation.

Rules live in a YAML file (rules/default.yaml is embedded in the
binary; detection.rules_file in the config replaces it). Each rule
has a kind, which picks the Go code that evaluates it, and params,
which hold the thresholds and lists that code reads. Every rule
must carry its rationale, false positives, analyst guidance and
the names of its positive and negative tests, or loading fails.
*/

package detection

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/rules"
)

const (
	KindAuthVolume          = "auth_volume"
	KindAuthFailureBurst    = "auth_failure_burst"
	KindFailuresThenSuccess = "failures_then_success"
	KindHTTPSensitivePaths  = "http_sensitive_paths"
	KindMultiServiceContact = "multi_service_contact"
	KindDiscoverySequence   = "discovery_sequence"
	KindTransferCommand     = "transfer_command"
	KindRedisConfigWrite    = "redis_config_write"
	KindSSHPortForward      = "ssh_port_forward"
	KindScannerUserAgent    = "scanner_user_agent"
)

var knownKinds = map[string]bool{
	KindAuthVolume: true, KindAuthFailureBurst: true,
	KindFailuresThenSuccess: true, KindHTTPSensitivePaths: true,
	KindMultiServiceContact: true, KindDiscoverySequence: true,
	KindTransferCommand: true, KindRedisConfigWrite: true,
	KindSSHPortForward: true, KindScannerUserAgent: true,
}

// kinds that count events inside a time window
var windowed = map[string]bool{
	KindAuthVolume: true, KindAuthFailureBurst: true,
	KindFailuresThenSuccess: true, KindHTTPSensitivePaths: true,
	KindMultiServiceContact: true, KindDiscoverySequence: true,
}

var ruleIDPattern = regexp.MustCompile(`^HLAB-[A-Z]+-[0-9]{3}$`)

type Params struct {
	Threshold int           `yaml:"threshold" json:"threshold,omitempty"`
	Window    time.Duration `yaml:"window" json:"window,omitempty"`
	Services  []string      `yaml:"services" json:"services,omitempty"`
	Paths     []string      `yaml:"paths" json:"paths,omitempty"`
	Commands  []string      `yaml:"commands" json:"commands,omitempty"`
	FileReads []string      `yaml:"file_reads" json:"file_reads,omitempty"`
}

type RuleTests struct {
	Positive []string `yaml:"positive" json:"positive"`
	Negative []string `yaml:"negative" json:"negative"`
}

type Rule struct {
	ID                  string        `yaml:"id" json:"id"`
	Version             int           `yaml:"version" json:"version"`
	Name                string        `yaml:"name" json:"name"`
	Kind                string        `yaml:"kind" json:"kind"`
	Enabled             bool          `yaml:"enabled" json:"enabled"`
	Severity            string        `yaml:"severity" json:"severity"`
	Confidence          string        `yaml:"confidence" json:"confidence"`
	ConfidenceRationale string        `yaml:"confidence_rationale" json:"confidence_rationale"`
	Description         string        `yaml:"description" json:"description"`
	Rationale           string        `yaml:"rationale" json:"rationale"`
	RequiredFields      []string      `yaml:"required_fields" json:"required_fields"`
	Params              Params        `yaml:"params" json:"params"`
	SuppressFor         time.Duration `yaml:"suppress_for" json:"suppress_for"`
	MITRE               []string      `yaml:"mitre" json:"mitre"`
	FalsePositives      []string      `yaml:"false_positives" json:"false_positives"`
	Guidance            []string      `yaml:"guidance" json:"guidance"`
	Tests               RuleTests     `yaml:"tests" json:"tests"`
}

type ruleFile struct {
	Rules []*Rule `yaml:"rules"`
}

// LoadRules reads rules from path, or the embedded defaults when
// path is empty.
func LoadRules(path string) ([]*Rule, string, error) {
	data := rules.Default
	source := "embedded rules/default.yaml"
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("reading rules %s: %w", path, err)
		}
		data, source = b, path
	}
	parsed, err := ParseRules(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", source, err)
	}
	return parsed, source, nil
}

// ParseRules decodes and validates a rules document.
func ParseRules(data []byte) ([]*Rule, error) {
	var f ruleFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing rules: %w", err)
	}
	if err := Validate(f.Rules); err != nil {
		return nil, err
	}
	sort.Slice(f.Rules, func(i, j int) bool {
		return f.Rules[i].ID < f.Rules[j].ID
	})
	return f.Rules, nil
}

// Validate checks every rule and returns all problems at once.
func Validate(rs []*Rule) error {
	idx := mitre.NewIndex()
	var problems []string
	seen := map[string]bool{}

	for i, r := range rs {
		where := fmt.Sprintf("rule %d (%s)", i+1, r.ID)
		add := func(format string, args ...any) {
			problems = append(problems, where+": "+fmt.Sprintf(format, args...))
		}
		if !ruleIDPattern.MatchString(r.ID) {
			add("id must look like HLAB-AUTH-001")
		}
		if seen[r.ID] {
			add("duplicate id")
		}
		seen[r.ID] = true
		if r.Version < 1 {
			add("version must be 1 or more")
		}
		if !knownKinds[r.Kind] {
			add("unknown kind %q", r.Kind)
		}
		switch r.Severity {
		case "low", "medium", "high", "critical":
		default:
			add("severity %q must be low, medium, high or critical", r.Severity)
		}
		switch r.Confidence {
		case "low", "medium", "high":
		default:
			add("confidence %q must be low, medium or high", r.Confidence)
		}
		for name, v := range map[string]string{
			"name": r.Name, "description": r.Description,
			"rationale": r.Rationale, "confidence_rationale": r.ConfidenceRationale,
		} {
			if strings.TrimSpace(v) == "" {
				add("%s is required", name)
			}
		}
		if len(r.RequiredFields) == 0 {
			add("required_fields is empty")
		}
		if len(r.FalsePositives) == 0 {
			add("false_positives is empty; write 'none known' if that is true")
		}
		if len(r.Guidance) == 0 {
			add("guidance is empty")
		}
		if len(r.Tests.Positive) == 0 || len(r.Tests.Negative) == 0 {
			add("needs at least one positive and one negative test name")
		}
		if r.SuppressFor <= 0 {
			add("suppress_for must be positive")
		}
		for _, t := range r.MITRE {
			if idx.Get(t) == nil {
				add("MITRE technique %s is not in the local catalogue", t)
			}
		}
		if windowed[r.Kind] {
			if r.Params.Threshold < 1 {
				add("params.threshold must be at least 1")
			}
			if r.Params.Window <= 0 {
				add("params.window must be positive")
			}
		}
		switch r.Kind {
		case KindHTTPSensitivePaths:
			if len(r.Params.Paths) == 0 {
				add("params.paths is empty")
			}
		case KindDiscoverySequence, KindTransferCommand, KindRedisConfigWrite:
			if len(r.Params.Commands) == 0 {
				add("params.commands is empty")
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid rules:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
