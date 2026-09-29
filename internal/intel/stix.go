/*
©AngelaMos | 2026
Modified by Hiten, 2026: pattern values are escaped, indicator
types follow the analyst status instead of always claiming
malicious activity, invented confidence was removed, and each
indicator carries its status and evidence event IDs.

stix.go

STIX 2.1 bundle export for selected observables.
*/

package intel

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	stixVersion   = "2.1"
	stixSpecVer   = "2.1"
	identityName  = "Honeypot SOC Investigation Lab"
	identityClass = "system"
)

type stixBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []interface{} `json:"objects"`
}

type stixIdentity struct {
	Type          string `json:"type"`
	SpecVersion   string `json:"spec_version"`
	ID            string `json:"id"`
	Created       string `json:"created"`
	Modified      string `json:"modified"`
	Name          string `json:"name"`
	IdentityClass string `json:"identity_class"`
}

type stixIndicator struct {
	Type           string   `json:"type"`
	SpecVersion    string   `json:"spec_version"`
	ID             string   `json:"id"`
	Created        string   `json:"created"`
	Modified       string   `json:"modified"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	IndicatorTypes []string `json:"indicator_types"`
	Pattern        string   `json:"pattern"`
	PatternType    string   `json:"pattern_type"`
	ValidFrom      string   `json:"valid_from"`
	Labels         []string `json:"labels,omitempty"`
	CreatedByRef   string   `json:"created_by_ref"`
	XStatus        string   `json:"x_hlab_status"`
	XInternal      bool     `json:"x_hlab_internal_address,omitempty"`
	XClaimed       bool     `json:"x_hlab_client_controlled,omitempty"`
	XSightings     int      `json:"x_hlab_sighting_count"`
	XEvidence      []string `json:"x_hlab_evidence_event_ids,omitempty"`
}

func GenerateSTIXBundle(
	iocs []*types.IOC,
) ([]byte, error) {
	identityID := fmt.Sprintf(
		"identity--%s",
		uuid.New().String(),
	)
	now := time.Now().UTC().Format(time.RFC3339)

	identity := stixIdentity{
		Type:          "identity",
		SpecVersion:   stixSpecVer,
		ID:            identityID,
		Created:       now,
		Modified:      now,
		Name:          identityName,
		IdentityClass: identityClass,
	}

	objects := []interface{}{identity}

	for _, ioc := range iocs {
		pattern := iocToSTIXPattern(ioc)
		if pattern == "" {
			continue
		}

		indicator := stixIndicator{
			Type:        "indicator",
			SpecVersion: stixSpecVer,
			ID: fmt.Sprintf(
				"indicator--%s",
				uuid.New().String(),
			),
			Created:  ioc.FirstSeen.UTC().Format(time.RFC3339),
			Modified: ioc.LastSeen.UTC().Format(time.RFC3339),
			Name: fmt.Sprintf(
				"%s: %s",
				ioc.Type.String(), ioc.Value,
			),
			Description:    stixDescription(ioc),
			IndicatorTypes: indicatorTypes(ioc),
			Pattern:        pattern,
			PatternType:    "stix",
			ValidFrom:      ioc.FirstSeen.UTC().Format(time.RFC3339),
			Labels:         ioc.Tags,
			CreatedByRef:   identityID,
			XStatus:        ioc.Status,
			XInternal:      ioc.Internal,
			XClaimed:       ioc.Claimed,
			XSightings:     ioc.SightCount,
		}
		for _, e := range ioc.Evidence {
			indicator.XEvidence = append(indicator.XEvidence, e.ID)
		}

		objects = append(objects, indicator)
	}

	bundle := stixBundle{
		Type: "bundle",
		ID: fmt.Sprintf(
			"bundle--%s",
			uuid.New().String(),
		),
		Objects: objects,
	}

	return json.MarshalIndent(bundle, "", "  ")
}

// escapeSTIX escapes a value for use inside a quoted STIX pattern
// string. Without this a URL containing a quote breaks the pattern.
func escapeSTIX(v string) string {
	return strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(v)
}

func iocToSTIXPattern(ioc *types.IOC) string {
	v := escapeSTIX(ioc.Value)
	switch ioc.Type {
	case types.IOCIPv4:
		return fmt.Sprintf(
			"[ipv4-addr:value = '%s']", v,
		)
	case types.IOCIPv6:
		return fmt.Sprintf(
			"[ipv6-addr:value = '%s']", v,
		)
	case types.IOCDomain:
		return fmt.Sprintf(
			"[domain-name:value = '%s']", v,
		)
	case types.IOCURL:
		return fmt.Sprintf(
			"[url:value = '%s']", v,
		)
	case types.IOCHashSHA256:
		return fmt.Sprintf(
			"[file:hashes.'SHA-256' = '%s']",
			v,
		)
	case types.IOCHashMD5:
		return fmt.Sprintf(
			"[file:hashes.MD5 = '%s']", v,
		)
	case types.IOCUserAgent:
		return fmt.Sprintf(
			"[network-traffic:extensions."+
				"'http-request-ext'."+
				"request_header.'User-Agent' = '%s']",
			v,
		)
	case types.IOCEmail:
		return fmt.Sprintf(
			"[email-addr:value = '%s']", v,
		)
	default:
		return ""
	}
}

func indicatorTypes(ioc *types.IOC) []string {
	switch ioc.Status {
	case types.ObservableConfirmed:
		return []string{"malicious-activity"}
	case types.ObservableSuspicious:
		return []string{"anomalous-activity"}
	case types.ObservableBenign:
		return []string{"benign"}
	default:
		return []string{"unknown"}
	}
}

func stixDescription(ioc *types.IOC) string {
	d := fmt.Sprintf(
		"Seen %d time(s) by a local honeypot lab between %s and %s. Analyst status: %s.",
		ioc.SightCount,
		ioc.FirstSeen.UTC().Format(time.RFC3339),
		ioc.LastSeen.UTC().Format(time.RFC3339),
		ioc.Status,
	)
	if ioc.Claimed {
		d += " The value is chosen by the client and may be spoofed."
	}
	if ioc.Internal {
		d += " This is an internal or loopback address."
	}
	return d
}
