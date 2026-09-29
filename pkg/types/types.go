/*
©AngelaMos | 2026
Modified by Hiten, 2026: destination address, persisted sequence,
origin label, connection.denied event, observable status fields,
and new detection, case, response and lab-run types.

types.go

Shared domain types for the hive honeypot network

Defines the core data structures that flow through every subsystem:
service enums, the unified event envelope, session and attacker
models, credential and IOC records, and the Service interface that
all honeypot protocols implement. Zero imports from internal packages.
*/

package types

import (
	"context"
	"encoding/json"
	"net"
	"time"
)

const Version = "0.2.0"

type ServiceType int

const (
	ServiceSSH ServiceType = iota
	ServiceHTTP
	ServiceFTP
	ServiceSMB
	ServiceMySQL
	ServiceRedis
)

var serviceNames = map[ServiceType]string{
	ServiceSSH:   "ssh",
	ServiceHTTP:  "http",
	ServiceFTP:   "ftp",
	ServiceSMB:   "smb",
	ServiceMySQL: "mysql",
	ServiceRedis: "redis",
}

var serviceLabels = map[ServiceType]string{
	ServiceSSH:   "SSH",
	ServiceHTTP:  "HTTP",
	ServiceFTP:   "FTP",
	ServiceSMB:   "SMB",
	ServiceMySQL: "MySQL",
	ServiceRedis: "Redis",
}

func (s ServiceType) String() string {
	return serviceNames[s]
}

func (s ServiceType) Label() string {
	return serviceLabels[s]
}

func (s ServiceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func ParseServiceType(s string) (ServiceType, bool) {
	for st, name := range serviceNames {
		if name == s {
			return st, true
		}
	}
	return ServiceSSH, false
}

type EventType int

const (
	EventConnect EventType = iota
	EventDisconnect
	EventLoginSuccess
	EventLoginFailed
	EventCommand
	EventCommandOutput
	EventFileUpload
	EventFileDownload
	EventRequest
	EventExploit
	EventScan
	EventConnectionDenied
)

var eventNames = map[EventType]string{
	EventConnect:          "connect",
	EventDisconnect:       "disconnect",
	EventLoginSuccess:     "login.success",
	EventLoginFailed:      "login.failed",
	EventCommand:          "command.input",
	EventCommandOutput:    "command.output",
	EventFileUpload:       "file.upload",
	EventFileDownload:     "file.download",
	EventRequest:          "request",
	EventExploit:          "exploit.attempt",
	EventScan:             "scan.detected",
	EventConnectionDenied: "connection.denied",
}

func (e EventType) String() string {
	return eventNames[e]
}

func (e EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func ParseEventType(s string) (EventType, bool) {
	for et, name := range eventNames {
		if name == s {
			return et, true
		}
	}
	return EventConnect, false
}

type Protocol int

const (
	ProtocolTCP Protocol = iota
	ProtocolUDP
)

var protocolNames = map[Protocol]string{
	ProtocolTCP: "tcp",
	ProtocolUDP: "udp",
}

func (p Protocol) String() string {
	return protocolNames[p]
}

func (p Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

type GeoInfo struct {
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         int     `json:"asn"`
	Org         string  `json:"org"`
}

type Event struct {
	ID            string          `json:"id"`
	SessionID     string          `json:"session_id"`
	SensorID      string          `json:"sensor_id"`
	Timestamp     time.Time       `json:"timestamp"`
	ReceivedAt    time.Time       `json:"received_at"`
	ServiceType   ServiceType     `json:"service_type"`
	EventType     EventType       `json:"event_type"`
	SourceIP      string          `json:"source_ip"`
	SourcePort    int             `json:"source_port"`
	DestIP        string          `json:"dest_ip,omitempty"`
	DestPort      int             `json:"dest_port"`
	Protocol      Protocol        `json:"protocol"`
	SchemaVersion int             `json:"schema_version"`
	Geo           *GeoInfo        `json:"geo,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	ServiceData   json.RawMessage `json:"service_data,omitempty"`
	// Seq is assigned by the database when the event is stored.
	// It only increases and is the cursor for missed-event recovery.
	Seq int64 `json:"seq,omitempty"`
	// Origin is "lab" when the source address is inside the
	// configured lab ranges, otherwise "external". It is a label
	// for the analyst and is never read by detection rules.
	Origin string `json:"origin,omitempty"`
}

// Ref returns the (id, timestamp) pair that identifies a stored
// event. The events table is partitioned by timestamp, so both
// parts are needed.
func (e *Event) Ref() EventRef {
	return EventRef{ID: e.ID, Timestamp: e.Timestamp}
}

// EventRef identifies one stored event.
type EventRef struct {
	ID        string    `json:"event_id"`
	Timestamp time.Time `json:"event_timestamp"`
}

type Session struct {
	ID              string      `json:"id"`
	SensorID        string      `json:"sensor_id"`
	StartedAt       time.Time   `json:"started_at"`
	EndedAt         *time.Time  `json:"ended_at,omitempty"`
	ServiceType     ServiceType `json:"service_type"`
	SourceIP        string      `json:"source_ip"`
	SourcePort      int         `json:"source_port"`
	DestPort        int         `json:"dest_port"`
	ClientVersion   string      `json:"client_version,omitempty"`
	LoginSuccess    bool        `json:"login_success"`
	Username        string      `json:"username,omitempty"`
	AuthMode        string      `json:"auth_mode,omitempty"`
	CommandCount    int         `json:"command_count"`
	MITRETechniques []string    `json:"mitre_techniques,omitempty"`
	RuleIDs         []string    `json:"rule_ids,omitempty"`
	LastActivity    *time.Time  `json:"last_activity,omitempty"`
	ThreatScore     int         `json:"threat_score"`
	Tags            []string    `json:"tags,omitempty"`
}

type Attacker struct {
	ID            int64     `json:"id"`
	IP            string    `json:"ip"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TotalEvents   int64     `json:"total_events"`
	TotalSessions int       `json:"total_sessions"`
	Geo           GeoInfo   `json:"geo"`
	ThreatScore   int       `json:"threat_score"`
	ToolFamily    string    `json:"tool_family,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
}

type Credential struct {
	ID          int64       `json:"id"`
	SessionID   string      `json:"session_id"`
	Timestamp   time.Time   `json:"timestamp"`
	ServiceType ServiceType `json:"service_type"`
	SourceIP    string      `json:"source_ip"`
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	PublicKey   string      `json:"public_key,omitempty"`
	AuthMethod  string      `json:"auth_method"`
	Success     bool        `json:"success"`
}

type CapturedFile struct {
	ID        int64       `json:"id"`
	SessionID string      `json:"session_id"`
	Timestamp time.Time   `json:"timestamp"`
	SourceIP  string      `json:"source_ip"`
	Service   ServiceType `json:"service"`
	Filename  string      `json:"filename"`
	Size      int64       `json:"size"`
	SHA256    string      `json:"sha256"`
	MD5       string      `json:"md5"`
	MimeType  string      `json:"mime_type"`
	Content   []byte      `json:"-"`
}

type IOCType int

const (
	IOCIPv4 IOCType = iota
	IOCIPv6
	IOCDomain
	IOCURL
	IOCHashSHA256
	IOCHashMD5
	IOCSSHKey
	IOCUserAgent
	IOCEmail
	IOCSSHClient
)

var iocTypeNames = map[IOCType]string{
	IOCIPv4:       "ipv4",
	IOCIPv6:       "ipv6",
	IOCDomain:     "domain",
	IOCURL:        "url",
	IOCHashSHA256: "sha256",
	IOCHashMD5:    "md5",
	IOCSSHKey:     "ssh-key",
	IOCUserAgent:  "user-agent",
	IOCEmail:      "email",
	IOCSSHClient:  "ssh-client",
}

func (t IOCType) String() string {
	return iocTypeNames[t]
}

func (t IOCType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func ParseIOCType(s string) (IOCType, bool) {
	for t, name := range iocTypeNames {
		if name == s {
			return t, true
		}
	}
	return IOCIPv4, false
}

// IOC is stored in the iocs table. The dashboard calls these
// observables: most are just things that were seen, and only an
// analyst decision makes one a confirmed indicator.
type IOC struct {
	ID         int64     `json:"id"`
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`
	Original   string    `json:"original_value,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	SightCount int       `json:"sight_count"`
	Confidence int       `json:"confidence"`
	Source     string    `json:"source"`
	Tags       []string  `json:"tags,omitempty"`
	// Status is observed, suspicious, confirmed or benign.
	Status string `json:"status"`
	// Internal is true for loopback, private and link-local
	// addresses. Internal values are never exported unless asked.
	Internal bool `json:"internal"`
	// Claimed marks values the client controls, such as a
	// User-Agent header.
	Claimed bool `json:"claimed"`
	// Evidence links, filled on detail requests.
	Evidence []ObservableEvidence `json:"evidence,omitempty"`
}

const (
	ObservableObserved   = "observed"
	ObservableSuspicious = "suspicious"
	ObservableConfirmed  = "confirmed"
	ObservableBenign     = "benign"
)

type ObservableEvidence struct {
	EventRef
	SessionID string    `json:"session_id"`
	LinkedAt  time.Time `json:"linked_at"`
}

type MITREDetection struct {
	ID          int64       `json:"id"`
	SessionID   string      `json:"session_id"`
	TechniqueID string      `json:"technique_id"`
	Tactic      string      `json:"tactic"`
	Confidence  int         `json:"confidence"`
	SourceIP    string      `json:"source_ip"`
	ServiceType ServiceType `json:"service_type"`
	Evidence    string      `json:"evidence"`
	DetectedAt  time.Time   `json:"detected_at"`
}

// Confidence levels used by rules. They describe how specific the
// matched behaviour is. They are not measured probabilities.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Detection is one rule match, with links to the events that
// caused it.
type Detection struct {
	ID              int64               `json:"id"`
	RuleID          string              `json:"rule_id"`
	RuleVersion     int                 `json:"rule_version"`
	RuleName        string              `json:"rule_name"`
	Severity        string              `json:"severity"`
	Confidence      string              `json:"confidence"`
	SensorID        string              `json:"sensor_id"`
	SourceIP        string              `json:"source_ip"`
	SessionID       string              `json:"session_id,omitempty"`
	ServiceType     ServiceType         `json:"service_type"`
	GroupKey        string              `json:"group_key"`
	FirstSeen       time.Time           `json:"first_seen"`
	LastSeen        time.Time           `json:"last_seen"`
	DetectedAt      time.Time           `json:"detected_at"`
	Explanation     string              `json:"explanation"`
	MatchedValues   map[string]any      `json:"matched_values"`
	MITRE           []string            `json:"mitre,omitempty"`
	SuppressedCount int                 `json:"suppressed_count"`
	CaseID          *int64              `json:"case_id,omitempty"`
	Evidence        []DetectionEvidence `json:"evidence,omitempty"`
}

// DetectionEvidence links a detection to an event. Role is
// "trigger" for the event that completed the match, "contributing"
// for earlier events in the window, and "repeat" for later events
// that matched again while the rule was suppressed.
type DetectionEvidence struct {
	EventRef
	Role string `json:"role"`
}

const (
	CaseNew           = "new"
	CaseInvestigating = "investigating"
	CaseClosed        = "closed"

	VerdictSuspicious   = "suspicious"
	VerdictBenign       = "benign"
	VerdictExpectedTest = "expected-test"
	VerdictInsufficient = "insufficient-evidence"
)

type Case struct {
	ID               int64      `json:"id"`
	Ref              string     `json:"ref"`
	Title            string     `json:"title"`
	Status           string     `json:"status"`
	Severity         string     `json:"severity"`
	Verdict          string     `json:"verdict,omitempty"`
	SensorID         string     `json:"sensor_id"`
	SourceIP         string     `json:"source_ip"`
	FirstActivity    time.Time  `json:"first_activity"`
	LastActivity     time.Time  `json:"last_activity"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	ResponseDecision string     `json:"response_decision,omitempty"`
	ClosureReason    string     `json:"closure_reason,omitempty"`
	MergedInto       *int64     `json:"merged_into,omitempty"`
	DetectionCount   int        `json:"detection_count"`
	EventCount       int        `json:"event_count"`
	SessionIDs       []string   `json:"session_ids,omitempty"`
	Services         []string   `json:"services,omitempty"`
	ClosedAt         *time.Time `json:"closed_at,omitempty"`
}

type CaseHistoryEntry struct {
	ID     int64          `json:"id"`
	CaseID int64          `json:"case_id"`
	At     time.Time      `json:"at"`
	Actor  string         `json:"actor"`
	Action string         `json:"action"`
	Detail map[string]any `json:"detail,omitempty"`
}

type CaseNote struct {
	ID     int64     `json:"id"`
	CaseID int64     `json:"case_id"`
	At     time.Time `json:"at"`
	Author string    `json:"author"`
	Body   string    `json:"body"`
}

// CaseEvent links an event to a case directly (analyst-added
// evidence). Events reached through detections are linked through
// detection_evidence instead.
type CaseEvent struct {
	EventRef
	AddedBy string    `json:"added_by"`
	Note    string    `json:"note,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

const (
	ActionPending  = "pending_approval"
	ActionRejected = "rejected"
	ActionActive   = "active"
	ActionFailed   = "failed"
	ActionExpired  = "expired"
	ActionReversed = "reversed"
)

// ResponseAction is one run of the restrict-source playbook.
type ResponseAction struct {
	ID           int64          `json:"id"`
	CaseID       int64          `json:"case_id"`
	Playbook     string         `json:"playbook"`
	SourceIP     string         `json:"source_ip"`
	SensorID     string         `json:"sensor_id"`
	Services     []string       `json:"services"`
	State        string         `json:"state"`
	Summary      string         `json:"summary"`
	RequestedAt  time.Time      `json:"requested_at"`
	DecidedAt    *time.Time     `json:"decided_at,omitempty"`
	DecidedBy    string         `json:"decided_by,omitempty"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	EndedAt      *time.Time     `json:"ended_at,omitempty"`
	Verification map[string]any `json:"verification,omitempty"`
	Error        string         `json:"error,omitempty"`
}

type ActionHistoryEntry struct {
	ID       int64          `json:"id"`
	ActionID int64          `json:"action_id"`
	At       time.Time      `json:"at"`
	Actor    string         `json:"actor"`
	From     string         `json:"from_state"`
	To       string         `json:"to_state"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// ScenarioRun is a stored result from the lab test runner.
type ScenarioRun struct {
	ID          int64          `json:"id"`
	RunID       string         `json:"run_id"`
	ScenarioID  string         `json:"scenario_id"`
	Kind        string         `json:"kind"`
	SourceIP    string         `json:"source_ip"`
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  time.Time      `json:"finished_at"`
	Passed      bool           `json:"passed"`
	Skipped     bool           `json:"skipped"`
	Expected    map[string]any `json:"expected"`
	Observed    map[string]any `json:"observed"`
	Failures    []string       `json:"failures,omitempty"`
	RunnerNotes string         `json:"notes,omitempty"`
}

type Sensor struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Region    string    `json:"region"`
	PublicIP  string    `json:"public_ip"`
	Services  []string  `json:"services"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
}

type Service interface {
	Name() string
	Start(ctx context.Context) error
}

func RemoteAddr(conn net.Conn) (string, int) {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "", 0
	}
	return addr.IP.String(), addr.Port
}
