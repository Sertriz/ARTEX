package cvematch

import "testing"

func TestParseCPE(t *testing.T) {
	cases := []struct {
		in              string
		vendor, product string
		version         string
		ok              bool
	}{
		{"cpe:/a:openbsd:openssh:8.2p1", "openbsd", "openssh", "8.2p1", true},
		{"cpe:/a:openbsd:openssh", "openbsd", "openssh", "", true},
		{"cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*", "openbsd", "openssh", "8.2", true},
		// NVD files OpenSSH 8.5p1 as version 8.5, update p1.
		{"cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*", "openbsd", "openssh", "8.5p1", true},
		// update "-" is "not applicable": no suffix.
		{"cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", "openbsd", "openssh", "9.3", true},
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
		if ok && (p.Vendor != c.vendor || p.Product != c.product || v != c.version) {
			t.Errorf("%q: got (%q,%q,%q) want (%q,%q,%q)", c.in, p.Vendor, p.Product, v, c.vendor, c.product, c.version)
		}
	}
}

func TestParseCPENameParts(t *testing.T) {
	c, ok := ParseCPEName("cpe:/o:canonical:ubuntu_linux")
	if !ok || c.Part != "o" || c.Vendor != "canonical" || c.Product != "ubuntu_linux" {
		t.Fatalf("got %+v ok=%v", c, ok)
	}
	// An update with no version yields no full version.
	if c, _ := ParseCPEName("cpe:2.3:o:microsoft:windows_7:-:sp1:*:*:*:*:*:*"); c.FullVersion() != "" {
		t.Errorf("full version = %q, want empty", c.FullVersion())
	}
}

func TestParseCPE23EscapedColon(t *testing.T) {
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

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"8.2p1 Ubuntu 4ubuntu0.5": "8.2p1",
		"2.4.41 (Ubuntu)":         "2.4.41",
		"v5.30.0":                 "5.30.0",
		"1.18.0":                  "1.18.0",
		"  9.6p1  ":               "9.6p1",
		"1.0.2k-fips":             "1.0.2k-fips",
		"unknown":                 "",
		"":                        "",
		"-":                       "",
		"5.5.5-10.3.39-MariaDB":   "5.5.5-10.3.39-mariadb", // the MariaDB prefix is stripped in Correlate
		"10.3.23 or earlier":      "",
		"2.4.X":                   "",
		"5.*":                     "",
		"1.0.2x":                  "1.0.2x",
	}
	for in, want := range cases {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDetectDistro(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"8.2p1 Ubuntu 4ubuntu0.5", "Ubuntu Linux; protocol 2.0"}, "ubuntu"},
		{[]string{"7.4p1 Debian 10+deb9u7"}, "debian"},
		{[]string{"9.2p1", "Debian GNU/Linux"}, "debian"},
		{[]string{"2.4.6 (CentOS)"}, "centos"},
		{[]string{"2.4.37 (Red Hat Enterprise Linux)"}, "rhel"},
		{[]string{"7.4", "protocol 2.0"}, ""},
		{[]string{"9.6", "FreeBSD 20240104"}, "freebsd"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := DetectDistro(c.in...); got != c.want {
			t.Errorf("DetectDistro(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	lt := [][2]string{
		{"8.0", "8.2"},
		{"8.2", "8.10"},  // numeric, not lexical
		{"1.0", "1.0.1"}, // shorter precedes
		{"8.2", "8.2p1"}, // numeric token precedes alpha token
		{"9.8", "9.8p1"}, // NVD's "<= 9.8" must exclude the 9.8p1 fix release
		{"9.3p1", "9.3p2"},
		{"1.0.1", "1.0.1f"},
		{"1.0.1f", "1.0.1g"},
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
	for _, p := range [][2]string{{"8.2", "8.2"}, {"1.0.0", "1.0.0"}, {"8.2p1", "8.2p1"}, {"1.0", "1-0"}} {
		if c := CompareVersions(p[0], p[1]); c != 0 {
			t.Errorf("CompareVersions(%q,%q)=%d want 0", p[0], p[1], c)
		}
	}
	// A digit run too long for an int must not wrap around to a small number.
	if CompareVersions("99999999999999999999999", "2") <= 0 {
		t.Error("overlong numeric token wrapped")
	}
}

func TestAliasKey(t *testing.T) {
	cases := map[string]string{
		"Microsoft-IIS":       "microsoft iis",
		"Microsoft IIS httpd": "microsoft iis httpd",
		"  Node.js  ":         "node js",
		"Apache/Tomcat":       "apache tomcat",
		"":                    "",
	}
	for in, want := range cases {
		if got := aliasKey(in); got != want {
			t.Errorf("aliasKey(%q) = %q, want %q", in, got, want)
		}
	}
}
