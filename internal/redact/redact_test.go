package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func TestServiceDataMasksKnownPlaces(t *testing.T) {
	raw := json.RawMessage(`{
		"username":"root","password":"hunter2","auth_mode":"accept-all",
		"headers":{"Authorization":"Basic cm9vdDpodW50ZXIy","Cookie":"sid=abc","Accept":"*/*"},
		"query":"user=admin&password=hunter2&page=1",
		"body":"log=admin&pwd=hunter2&wp-submit=Log+In",
		"raw":"AUTH hunter2",
		"command":"mysql -uroot -phunter2 -e 'show databases'"
	}`)
	out := string(ServiceData(raw))
	if strings.Contains(out, "hunter2") || strings.Contains(out, "cm9vdDpodW50ZXIy") || strings.Contains(out, "sid=abc") {
		t.Fatalf("secret left in output: %s", out)
	}
	for _, keep := range []string{`"username":"root"`, `"Accept":"*/*"`, "user=admin", "page=1", "log=admin", "accept-all"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-secret %q was removed: %s", keep, out)
		}
	}
}

func TestText(t *testing.T) {
	cases := map[string]string{
		"wget http://bob:s3cret@files.example.test/x.sh": "s3cret",
		"CONFIG SET requirepass s3cret":                  "s3cret",
		"CREATE USER 'x'@'%' IDENTIFIED BY 's3cret'":     "s3cret",
		"SET PASSWORD = PASSWORD('s3cret')":              "s3cret",
		"curl --password=s3cret http://a.test":           "s3cret",
		"sshpass -p s3cret ssh root@10.0.0.5":            "s3cret",
		"echo 'root:s3cret' | chpasswd":                  "s3cret",
		"AUTH default s3cret":                            "s3cret",
	}
	for in, secret := range cases {
		if out := Text(in); strings.Contains(out, secret) {
			t.Errorf("%q -> %q still contains the secret", in, out)
		}
	}
	for _, same := range []string{"uname -a", "cat /etc/passwd", "ls -la /home", "GET /index.html"} {
		if Text(same) != same {
			t.Errorf("%q changed to %q", same, Text(same))
		}
	}
}

func TestEventCopyLeavesOriginal(t *testing.T) {
	ev := &types.Event{ServiceData: json.RawMessage(`{"password":"x1"}`)}
	m := Event(ev)
	if strings.Contains(string(m.ServiceData), "x1") || !strings.Contains(string(ev.ServiceData), "x1") {
		t.Fatal("masking must return a copy and leave the original")
	}
}

func TestInvalidJSONUnchanged(t *testing.T) {
	if got := string(ServiceData(json.RawMessage(`not json`))); got != "not json" {
		t.Fatal(got)
	}
}
