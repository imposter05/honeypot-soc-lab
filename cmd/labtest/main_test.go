package main

import "testing"

func TestParsePool(t *testing.T) {
	if a, b, err := parsePool("127.0.0.10-127.0.0.99"); err != nil || a.String() != "127.0.0.10" || b.String() != "127.0.0.99" {
		t.Fatalf("%v %v %v", a, b, err)
	}
	for _, bad := range []string{"127.0.0.10", "10.0.0.1-10.0.0.9", "127.0.0.99-127.0.0.10", "x-y"} {
		if _, _, err := parsePool(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
