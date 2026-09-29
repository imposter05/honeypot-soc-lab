/*
©AngelaMos | 2026
Modified by Hiten, 2026: a configured database that fails to open
is an error, and lookups with no answer return nil instead of an
empty record (which upstream stored as country "" at 0,0).

lookup.go

GeoIP resolution using MaxMind GeoLite2 database

Resolves IP addresses to geographic location, ASN, and organization.
Returns a zero-value GeoInfo gracefully when the database file is
missing, allowing the system to operate without a MaxMind account
during local development.
*/

package geo

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type mmdbRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Traits struct {
		AutonomousSystemNumber       int    `maxminddb:"autonomous_system_number"`
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	} `maxminddb:"traits"`
}

type Lookup struct {
	reader *maxminddb.Reader
}

// NewLookup opens a MaxMind database. An empty path means GeoIP is
// off; a path that cannot be opened is an error rather than being
// ignored, so a typo in the config is noticed.
func NewLookup(dbPath string) (*Lookup, error) {
	if dbPath == "" {
		return &Lookup{}, nil
	}
	reader, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening GeoIP database %s: %w", dbPath, err)
	}
	return &Lookup{reader: reader}, nil
}

func (l *Lookup) Enabled() bool { return l.reader != nil }

// Resolve returns nil (not an empty record) when GeoIP is off or
// the address is internal, so no location is stored for it.
func (l *Lookup) Resolve(ip string) (*types.GeoInfo, error) {
	if l.reader == nil {
		return nil, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid ip: %s", ip)
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() {
		return nil, nil
	}
	var record mmdbRecord
	if err := l.reader.Lookup(parsed, &record); err != nil {
		return nil, fmt.Errorf("geoip lookup: %w", err)
	}
	if record.Country.ISOCode == "" {
		return nil, nil
	}
	return &types.GeoInfo{
		CountryCode: record.Country.ISOCode,
		Country:     record.Country.Names["en"],
		City:        record.City.Names["en"],
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		ASN:         record.Traits.AutonomousSystemNumber,
		Org:         record.Traits.AutonomousSystemOrganization,
	}, nil
}

func (l *Lookup) Close() error {
	if l.reader != nil {
		return l.reader.Close()
	}
	return nil
}
