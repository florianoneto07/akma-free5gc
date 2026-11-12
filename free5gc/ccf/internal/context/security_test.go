package context

import "testing"

func TestParseScope(t *testing.T) {
	for in, want := range map[string]string{
		"3gpp#nef-aef:3gpp-akma":                         "3gpp#nef-aef:3gpp-akma",
		"3gpp#b:y,x;a:z":                                 "3gpp#a:z;b:x,y",
		"3gpp#nef-aef:3gpp-akma,3gpp-akma":               "3gpp#nef-aef:3gpp-akma",
		"3gpp#aef-jiangsu-nanjing:3gpp-monitoring-event": "3gpp#aef-jiangsu-nanjing:3gpp-monitoring-event",
	} {
		s, err := ParseScope(in)
		if err != nil || s.String() != want {
			t.Fatalf("%q: %q %v", in, s, err)
		}
	}
	for _, in := range []string{
		"", "nef-aef:3gpp-akma", "3gpp#", "3gpp#nef-aef", "3gpp#:3gpp-akma", "3gpp#nef-aef:",
		"3gpp#nef-aef:3gpp-akma,", "3gpp#nef-aef:3gpp-akma extra", "3gpp#nef-aef:a:res.x",
	} {
		if _, err := ParseScope(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}
