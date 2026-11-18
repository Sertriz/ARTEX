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
		"8.2p1 Ubuntu 4ubuntu0.5":          "8.2p1",
		"2.4.41 (Ubuntu)":                  "2.4.41",
		"v5.30.0":                          "5.30.0",
		"1.18.0":                           "1.18.0",
		"  9.6p1  ":                        "9.6p1",
		"1.0.2k-fips":                      "1.0.2k-fips",
		"unknown":                          "",
		"":                                 "",
		"-":                                "",
		"5.5.5-10.3.39-MariaDB":            "5.5.5-10.3.39-mariadb", // the MariaDB prefix is stripped in Correlate
		"10.3.23 or earlier":               "",
		"3.11 or later":                    "",
		"9.6.20 - 9.6.23 or 11.14 - 11.18": "",
		"1.6.0 - 1.9.0":                    "",
		"2.3.2 - 4.1.0":                    "",
		"5.12.0 - 5.15.4":                  "",
		"2.4.X":                            "",
		"5.*":                              "",
		"1.0.2x":                           "1.0.2x",
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

func TestStripPortable(t *testing.T) {
	cases := map[string]string{"7.9p1": "7.9", "9.6p12": "9.6", "7.9": "7.9", "1.0.2p": "1.0.2p", "p1": "p1"}
	for in, want := range cases {
		if got := stripPortable(in); got != want {
			t.Errorf("stripPortable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProductVersion(t *testing.T) {
	mysql := Product{Vendor: "oracle", Product: "mysql"}
	cases := []struct {
		p    Product
		in   string
		want string
	}{
		{mysql, "8.0.35-0ubuntu0.22.04.1", "8.0.35"},
		{mysql, "5.7.33-log", "5.7.33"},
		{Product{Vendor: "mysql", Product: "mysql"}, "8.0.35-27", "8.0.35"},
		{mysql, "8.0.35", "8.0.35"},
		{Product{Vendor: "mariadb", Product: "mariadb"}, "5.5.5-10.3.39", "10.3.39"},
		{Product{Vendor: "mariadb", Product: "mariadb"}, "5.5.5-10.3.39-mariadb", "10.3.39"},
		{Product{Vendor: "x", Product: "y"}, "1.0-rc1", "1.0-rc1"}, // a dash means something elsewhere
	}
	for _, c := range cases {
		if got := productVersion(c.p, c.in); got != c.want {
			t.Errorf("productVersion(%v, %q) = %q, want %q", c.p, c.in, got, c.want)
		}
	}
}

func TestPlatforms(t *testing.T) {
	cpe := func(s string) CPE { c, _ := ParseCPEName(s); return c }
	if got := platformOf(cpe("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*")); got != PlatformWindows {
		t.Errorf("windows = %v", got)
	}
	if got := platformOf(cpe("cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*")); got != PlatformLinux|PlatformDebian {
		t.Errorf("ubuntu = %v", got)
	}
	if got := platformOf(cpe("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*")); got != PlatformLinux {
		t.Errorf("linux kernel = %v", got)
	}
	for _, s := range []string{"cpe:2.3:o:redhat:fedora_core:4:*:*:*:*:*:*:*", "cpe:2.3:o:redhat:desktop_workstation:5:*:*:*:*:*:*:*",
		"cpe:2.3:o:redhat:enterprise_mrg:2.0:*:*:*:*:*:*:*", "cpe:2.3:o:redhat:fedora:9:*:*:*:*:*:*:*"} {
		if got := platformOf(cpe(s)); got != PlatformLinux|PlatformRedHat {
			t.Errorf("%s = %v", s, got.Names())
		}
	}
	for s, want := range map[string]PlatformSet{
		"cpe:2.3:a:redhat:jboss_web_server:3.0:*:*:*:*:*:*:*": PlatformOther, // an application, not an OS
		"cpe:2.3:o:opensuse_project:leap:15.0:*:*:*:*:*:*:*":  PlatformLinux | PlatformSUSE,
		"cpe:2.3:o:novell:opensuse:13.2:*:*:*:*:*:*:*":        PlatformLinux | PlatformSUSE,
		"cpe:2.3:o:raspberrypi:raspbian:-:*:*:*:*:*:*:*":      PlatformLinux | PlatformDebian,
		"cpe:2.3:o:novell:netware:6.5:*:*:*:*:*:*:*":          PlatformOther,
	} {
		if got := platformOf(cpe(s)); got != want {
			t.Errorf("%s = %v, want %v", s, got.Names(), want.Names())
		}
	}
	if got := platformOf(cpe("cpe:2.3:h:cisco:asa_5505:-:*:*:*:*:*:*:*")); got != PlatformOther {
		t.Errorf("cisco = %v", got)
	}
	cases := []struct {
		name   string
		cpes   []CPE
		distro string
		texts  []string
		want   PlatformSet
	}{
		{"os cpe", []CPE{cpe("cpe:/o:microsoft:windows")}, "", nil, PlatformWindows},
		{"distro", nil, "ubuntu", nil, PlatformLinux},
		{"freebsd", nil, "freebsd", nil, PlatformBSD},
		{"iis header", nil, "", []string{"Microsoft-IIS/10.0"}, PlatformWindows},
		{"unix comment", nil, "", []string{"Apache/2.4.49 (Unix)"}, platformUnix},
		{"unknown", nil, "", []string{"nginx/1.18.0"}, 0},
	}
	for _, c := range cases {
		if got := observedPlatform(c.cpes, c.distro, c.texts...); got != c.want {
			t.Errorf("%s: observedPlatform = %v, want %v", c.name, got, c.want)
		}
	}
	if got := observedPlatform([]CPE{cpe("cpe:/o:alpinelinux:alpine_linux")}, "alpine"); got != PlatformLinux {
		t.Errorf("an observed distro must not carry lineage bits: %v", got)
	}
	if !contradicts(PlatformWindows, PlatformLinux, "") || !contradicts(PlatformWindows, platformUnix, "") {
		t.Error("a Windows-only record must not apply to a Linux/Unix host")
	}
	if contradicts(PlatformWindows, 0, "") || contradicts(0, PlatformLinux, "") || contradicts(PlatformWindows|PlatformOther, PlatformLinux, "") || contradicts(PlatformWindows, PlatformWindows, "") {
		t.Error("unknown, unrestricted, other-platform and matching cases must not contradict")
	}
}

// TestDistroPlatforms covers records NVD limits to Linux distributions.
func TestDistroPlatforms(t *testing.T) {
	alpine := PlatformLinux | PlatformAlpine
	cases := []struct {
		rec, obs                 PlatformSet
		distro                   string
		contradicts, conditional bool
	}{
		{alpine, PlatformLinux, "ubuntu", true, false},  // another distribution
		{alpine, PlatformLinux, "rocky", true, false},   // another lineage
		{alpine, PlatformLinux, "alpine", false, false}, // the distribution named
		{alpine, PlatformLinux, "", false, true},        // Linux, distribution unknown
		{alpine, 0, "", false, true},                    // nothing known
		{alpine, PlatformWindows, "", true, false},      // another family
		{alpine, platformUnix, "", false, true},         // "(Unix)": maybe Alpine
		{alpine, PlatformBSD, "freebsd", true, false},
		// Lineages: a record for RHEL holds on Rocky, one for Debian on Ubuntu.
		{PlatformLinux | PlatformRedHat, PlatformLinux, "rocky", false, false},
		{PlatformLinux | PlatformDebian, PlatformLinux, "ubuntu", false, false},
		{PlatformLinux | PlatformDebian | PlatformRedHat, PlatformLinux, "fedora", false, false},
		// A family-only record is unchanged by the distribution.
		{PlatformLinux, PlatformLinux, "ubuntu", false, false},
		{PlatformWindows, 0, "", false, true},
		// A record that also names a platform outside the known families (an
		// application such as JBoss Web Server, an unknown OS) is never
		// contradicted: it is conditional where it mismatches the known ones.
		{PlatformLinux | PlatformRedHat | PlatformOther, PlatformLinux, "ubuntu", false, true},
		{PlatformLinux | PlatformRedHat | PlatformOther, PlatformLinux, "rocky", false, false},
		{PlatformWindows | PlatformOther, PlatformLinux, "", false, true},
		{PlatformWindows | PlatformOther, PlatformWindows, "", false, false},
		{PlatformOther, PlatformLinux, "ubuntu", false, false},
	}
	for _, c := range cases {
		if got := contradicts(c.rec, c.obs, c.distro); got != c.contradicts {
			t.Errorf("contradicts(%v, %v, %q) = %v", c.rec.Names(), c.obs.Names(), c.distro, got)
		}
		if got := conditional(c.rec, c.obs, c.distro); got != c.conditional {
			t.Errorf("conditional(%v, %v, %q) = %v", c.rec.Names(), c.obs.Names(), c.distro, got)
		}
	}
	if got := alpine.Names(); len(got) != 1 || got[0] != "alpine" {
		t.Errorf("names = %v, want [alpine]", got)
	}
	if got := (PlatformLinux | PlatformDebian | PlatformRedHat).Names(); len(got) != 2 || got[0] != "debian" || got[1] != "redhat" {
		t.Errorf("names = %v, want [debian redhat]", got)
	}
}

func TestParseCPEUpdateAndEdition(t *testing.T) {
	cases := []struct {
		in        string
		update    string
		updateAny bool
		edition   string
	}{
		{"cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*", "", true, ""},
		{"cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", "", false, ""},
		{"cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", "p1", false, ""},
		{"cpe:2.3:a:isc:bind:*:*:*:*:supported_preview:*:*:*", "", true, "supported_preview"},
		{"cpe:2.3:a:isc:bind:*:*:*:*:-:*:*:*", "", true, ""},
		{"cpe:/a:openbsd:openssh:8.2p1", "", true, ""},
	}
	for _, c := range cases {
		got, ok := ParseCPEName(c.in)
		if !ok || got.Update != c.update || got.UpdateAny != c.updateAny || got.SWEdition != c.edition {
			t.Errorf("%s: update %q any %v edition %q", c.in, got.Update, got.UpdateAny, got.SWEdition)
		}
	}
}
