package codec

import (
	"errors"
	"strings"
	"testing"

	"github.com/florianoneto07/akma-free5gc/shared/akma/kdf"
)

func key() kdf.Key {
	var k kdf.Key
	for i := range k {
		k[i] = byte(0xF0 + i%16)
	}
	return k
}

func TestHexKey(t *testing.T) {
	s := HexKey(key())
	if len(s) != 64 || s != strings.ToLower(s) {
		t.Fatalf("HexKey = %q, want 64 lowercase characters", s)
	}
	for _, in := range []string{s, strings.ToUpper(s)} {
		k, err := ParseHexKey(in)
		if err != nil || k != key() {
			t.Fatalf("ParseHexKey(%q): %v", in, err)
		}
	}
}

func TestParseHexKeyMalformed(t *testing.T) {
	s := HexKey(key())
	for _, in := range []string{
		s[:63],      // 63 characters
		s + "0",     // 65 characters
		"g" + s[1:], // not hexadecimal
		"x" + s,     // pattern must be anchored
		s + "x",     // pattern must be anchored
		"",
	} {
		if _, err := ParseHexKey(in); !errors.Is(err, ErrMalformedKey) {
			t.Errorf("ParseHexKey(%q): err = %v", in, err)
		}
	}
}

func TestBase64Key(t *testing.T) {
	s := Base64Key(key())
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		t.Fatalf("Base64Key = %q", s)
	}
}
