package cvematch

import "testing"

func TestParseCPE(t *testing.T) {
	cases := []struct {
		in              string
		vendor, product string
		version         string
		ok              bool
	}{
		{"cpe:/a:openbsd:openssh:8.2", "openbsd", "openssh", "8.2", true},
		{"cpe:/a:openbsd:openssh", "openbsd", "openssh", "", true},
		{"cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*", "openbsd", "openssh", "8.2", true},
		{"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "openbsd", "openssh", "", true},
		{"cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*", "linux", "linux_kernel", "5.15", true},
		{"cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*", "", "", "", false}, // hardware rejected
		{"not-a-cpe", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		p, v, ok := ParseCPE(c.in)
		if ok != c.ok {
			t.Fatalf("%q: ok=%v want %v", c.in, ok, c.ok)
		}
		if !ok {
			continue
		}
		if p.Vendor != c.vendor || p.Product != c.product || v != c.version {
			t.Errorf("%q: got (%q,%q,%q) want (%q,%q,%q)", c.in, p.Vendor, p.Product, v, c.vendor, c.product, c.version)
		}
	}
}

func TestParseCPE23EscapedColon(t *testing.T) {
	// A product field containing an escaped colon must not be split.
	p, v, ok := ParseCPE(`cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*`)
	if !ok || p.Product != "pro:duct" || v != "1.0" {
		t.Fatalf("got ok=%v product=%q version=%q", ok, p.Product, v)
	}
}

func TestNormalizeProductName(t *testing.T) {
	cases := map[string]Product{
		"OpenSSH":          {Product: "openssh"},
		"nginx":            {Product: "nginx"},
		"Apache httpd":     {Product: "apache_httpd"},
		"Microsoft IIS/10": {Product: "microsoft_iis10"},
		"  ":               {},
		"()/":              {},
	}
	for in, want := range cases {
		if got := NormalizeProductName(in); got != want {
			t.Errorf("%q: got %+v want %+v", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	lt := [][2]string{
		{"8.0", "8.2"},
		{"8.2", "8.10"},  // numeric, not lexical
		{"1.0", "1.0.1"}, // shorter precedes
		{"8.2", "8.2p1"}, // numeric token precedes alpha token
		{"1.0.2k", "1.0.2m"},
		{"4.92", "4.94"},
		{"1.2.3", "1.2.3.1"},
	}
	for _, p := range lt {
		if c := CompareVersions(p[0], p[1]); c >= 0 {
			t.Errorf("CompareVersions(%q,%q)=%d want <0", p[0], p[1], c)
		}
		if c := CompareVersions(p[1], p[0]); c <= 0 {
			t.Errorf("CompareVersions(%q,%q)=%d want >0", p[1], p[0], c)
		}
	}
	eq := [][2]string{{"8.2", "8.2"}, {"1.0.0", "1.0.0"}, {"8.2p1", "8.2p1"}}
	for _, p := range eq {
		if c := CompareVersions(p[0], p[1]); c != 0 {
			t.Errorf("CompareVersions(%q,%q)=%d want 0", p[0], p[1], c)
		}
	}
}
