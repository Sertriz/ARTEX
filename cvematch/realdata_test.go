package cvematch

import (
	"sort"
	"strings"
	"testing"
)

// testdata/nvd holds real NVD CVE API 2.0 records (US-government public domain),
// trimmed to the fields correlation reads (configurations kept whole):
//   - real-sample.jsonl: CVE-2021-41617, CVE-2023-38408 (OpenSSH), CVE-2021-41773
//     (Apache httpd 2.4.49), CVE-2021-23017 (nginx, filed under f5), CVE-2014-0160
//     (OpenSSL, Heartbleed), CVE-2011-2523 (vsftpd 2.3.4).
//   - real-sample-2.jsonl: OpenSSH "<= X" records (CVE-2019-6111 <= 7.9,
//     CVE-2018-15473 <= 7.7, CVE-2016-20012 <= 8.7, CVE-2016-6210 "*:p2" <= 7.2),
//     Windows-only AND configurations (CVE-2024-4577 PHP-CGI, CVE-2019-0232 Tomcat
//     CGI), and records hit by nmap's series/range versions and MySQL build
//     suffixes (CVE-2020-28017 Exim, CVE-2023-24329 Python, CVE-2021-27212
//     OpenLDAP, CVE-2024-20961 MySQL, CVE-2021-32027 PostgreSQL, CVE-2023-46604
//     ActiveMQ).
//   - real-sample-3.jsonl: ranged criteria with non-patch updates (CVE-2023-50868
//     BIND "*:s1", CVE-2008-7265 ProFTPD "*:rc2") and CVE-2006-5051, an OpenSSH
//     "before 4.4" filed as "<= 4.4" (an erratum).
//   - real-sample-4.jsonl: OpenSSH pins with update ANY (CVE-2020-12062 "8.2:*",
//     CVE-2023-25136 "9.1:*"), and beside a portable pin of the same release
//     (CVE-2016-0777 "7.1:*" and "7.1:p1", CVE-2003-0787 "3.7.1:*" and
//     "3.7.1p1:*"), BIND Supported Preview ranges (CVE-2026-10723, CVE-2023-2829
//     "9.16.8-S1 through 9.16.41-S1"), records limited to distributions
//     (CVE-2026-123158 OpenSSH on Alpine Linux, CVE-2015-1565 on Windows,
//     novell:opensuse or RHEL, CVE-2007-5795 with a Debian-only and a plain
//     configuration, CVE-2009-2939 spelled o:ubuntu:ubuntu_linux, CVE-2022-23238
//     with linux_kernel among its distributions, CVE-2022-46340 limited to RHEL
//     by one configuration while another marks Debian vulnerable), ProFTPD's
//     "1.3.5:*" pin fixed in 1.3.5a (CVE-2015-3306), and OpenSSH errata
//     (CVE-2011-4327 "before 5.8p2" filed "<= 5.8", CVE-2002-0575 pinning 2.9.9).
//   - CVE-2024-6387.json.gz: the full, untrimmed regreSSHion record, gzipped.
func loadRealData(t *testing.T) *NVDSource {
	t.Helper()
	src, err := LoadNVDDir("testdata/nvd")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	if st := src.Stats(); st.Files != 5 || st.ErrorFiles != 0 || st.CVEs != 37 {
		t.Fatalf("testdata stats %+v, want 5 files and 37 CVEs", st)
	}
	return src
}

func confirmedIDs(r Result) []string {
	var out []string
	for _, c := range r.Confirmed() {
		out = append(out, c.CVE)
	}
	sort.Strings(out)
	return out
}

func TestRealDataScenarios(t *testing.T) {
	src := loadRealData(t)
	cases := []struct {
		name string
		obs  Observation
		want []string // version-confirmed CVEs, sorted
	}{
		{"openssh 8.2p1 (Ubuntu 20.04)",
			Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:canonical:ubuntu_linux"}, Version: "8.2p1 Ubuntu 4ubuntu0.5"},
			[]string{"CVE-2016-20012", "CVE-2020-12062", "CVE-2021-41617", "CVE-2023-38408"}},
		// CVE-2026-123158 (before 10.6p2, Alpine only) is kept below as a lead
		// conditional on the platform, which these observations do not show.
		// regreSSHion: NVD pins 8.5p1 and ranges 8.6..9.8.
		{"openssh 8.5p1 pinned", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.5p1"}},
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408", "CVE-2024-6387", "CVE-2026-123158"}},
		{"openssh 9.6p1", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}},
			[]string{"CVE-2024-6387", "CVE-2026-123158"}},
		// 9.8p1 is the regreSSHion fix: outside "<= 9.8".
		{"openssh 9.8p1 fixed", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.8p1"}}, []string{"CVE-2026-123158"}},
		// CVE-2023-38408 pins 9.3 and 9.3p1; 9.3p2 is the fix.
		{"openssh 9.3p1 pinned", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.3p1"}},
			[]string{"CVE-2023-38408", "CVE-2024-6387", "CVE-2026-123158"}},
		{"openssh 9.3p2 fixed for 38408", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.3p2"}},
			[]string{"CVE-2024-6387", "CVE-2026-123158"}},
		// The bare product name, as httpx or a banner reports it.
		{"OpenSSH by name", Observation{Product: "OpenSSH", Version: "8.2p1"},
			[]string{"CVE-2016-20012", "CVE-2020-12062", "CVE-2021-41617", "CVE-2023-38408", "CVE-2026-123158"}},
		{"apache 2.4.49", Observation{CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}}, []string{"CVE-2021-41773"}},
		{"apache 2.4.50", Observation{CPEs: []string{"cpe:/a:apache:http_server:2.4.50"}}, nil},
		// nmap still says igor_sysoev; NVD files this CVE under f5.
		{"nginx via nmap's stale vendor", Observation{CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.18.0"}}, []string{"CVE-2021-23017"}},
		{"nginx 1.20.1 fixed", Observation{CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.20.1"}}, nil},
		{"openssl 1.0.1f heartbleed", Observation{CPEs: []string{"cpe:/a:openssl:openssl:1.0.1f"}}, []string{"CVE-2014-0160"}},
		{"openssl 1.0.1g fixed", Observation{CPEs: []string{"cpe:/a:openssl:openssl:1.0.1g"}}, nil},
		{"openssl 1.0.2k other branch", Observation{CPEs: []string{"cpe:/a:openssl:openssl:1.0.2k"}}, nil},
		// nmap says vsftpd:vsftpd; NVD says vsftpd_project:vsftpd.
		{"vsftpd 2.3.4 backdoor", Observation{CPEs: []string{"cpe:/a:vsftpd:vsftpd:2.3.4"}}, []string{"CVE-2011-2523"}},
		{"vsftpd 3.0.3", Observation{CPEs: []string{"cpe:/a:vsftpd:vsftpd:3.0.3"}}, nil},
		// CVE-2021-41617 also lists oracle:http_server 12.2.1.x: an Apache
		// observation must not inherit it.
		{"apache with an oracle-like version", Observation{CPEs: []string{"cpe:/a:apache:http_server:12.2.1.3.0"}}, nil},

		// NVD's "<= X" for OpenSSH includes the portable Xp1 every Linux sshd reports.
		{"openssh 7.9p1 (Debian 10)", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:7.9p1"}, Version: "7.9p1 Debian 10+deb10u2"},
			[]string{"CVE-2016-20012", "CVE-2019-6111", "CVE-2021-41617", "CVE-2023-38408"}},
		{"openssh 7.7p1", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:7.7p1"}},
			[]string{"CVE-2016-20012", "CVE-2018-15473", "CVE-2019-6111", "CVE-2021-41617", "CVE-2023-38408", "CVE-2026-123158"}},
		// CVE-2016-6210 is filed "openssh:*:p2 <= 7.2": up to 7.2p2.
		{"openssh 7.2p2 (Ubuntu 16.04)", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:7.2p2"}},
			[]string{"CVE-2016-20012", "CVE-2016-6210", "CVE-2018-15473", "CVE-2019-6111", "CVE-2021-41617", "CVE-2023-38408", "CVE-2026-123158"}},
		{"openssh 8.7p1", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.7p1"}},
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408", "CVE-2024-6387", "CVE-2026-123158"}},
		// regreSSHion's NVD bound "<= 9.8" is an erratum: 9.8 is the fix.
		{"openssh 9.8 openbsd", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.8"}}, []string{"CVE-2026-123158"}},

		// AND configurations: Windows only.
		{"php 8.1.2 on ubuntu", Observation{Product: "PHP", Version: "8.1.2", Extra: "Apache/2.4.52 (Ubuntu)"}, nil},
		{"php 8.1.2 on windows", Observation{Product: "PHP", Version: "8.1.2", Extra: "Microsoft-IIS/10.0"}, []string{"CVE-2024-4577"}},
		{"tomcat 9.0.17 on linux", Observation{CPEs: []string{"cpe:/a:apache:tomcat:9.0.17", "cpe:/o:linux:linux_kernel"}}, nil},

		// nmap series, bounds and ranges are not versions.
		{"exim 4.X", Observation{CPEs: []string{"cpe:/a:exim:exim:4"}, Version: "4.X"}, nil},
		{"exim 4.92", Observation{CPEs: []string{"cpe:/a:exim:exim:4.92"}, Version: "4.92"}, []string{"CVE-2020-28017"}},
		{"python 3.11 or later", Observation{CPEs: []string{"cpe:/a:python:python:3"}, Version: "3.11 or later"}, nil},
		{"openldap 2.4.X", Observation{CPEs: []string{"cpe:/a:openldap:openldap:2.4"}, Version: "2.4.X"}, nil},
		{"activemq range", Observation{CPEs: []string{"cpe:/a:apache:activemq:5"}, Version: "5.12.0 - 5.15.4"}, nil},
		{"activemq 5.15.15", Observation{CPEs: []string{"cpe:/a:apache:activemq:5.15.15"}}, []string{"CVE-2023-46604"}},
		{"postgresql range", Observation{CPEs: []string{"cpe:/a:postgresql:postgresql"}, Version: "9.6.20 - 9.6.23 or 11.14 - 11.18"}, nil},
		{"postgresql 9.6.20", Observation{CPEs: []string{"cpe:/a:postgresql:postgresql:9.6.20"}}, []string{"CVE-2021-32027"}},
		// The MySQL build suffix is not a later release.
		{"mysql 8.0.35 ubuntu build", Observation{CPEs: []string{"cpe:/a:mysql:mysql:8.0.35-0ubuntu0.22.04.1"}, Product: "MySQL"}, []string{"CVE-2024-20961"}},
	}
	for _, c := range cases {
		res := CorrelateResult(c.obs, src)
		got := confirmedIDs(res)
		if len(got) != len(c.want) || (len(got) > 0 && !equal(got, c.want)) {
			t.Errorf("%s: confirmed %v, want %v (version %q, products %v)", c.name, got, c.want, res.Version, res.Products)
		}
	}
}

func TestRealDataBackportFlag(t *testing.T) {
	src := loadRealData(t)
	res := CorrelateResult(Observation{
		CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:canonical:ubuntu_linux"}, Version: "8.2p1 Ubuntu 4ubuntu0.5",
	}, src)
	if res.Distro != "ubuntu" {
		t.Fatalf("distro = %q", res.Distro)
	}
	for _, c := range res.Confirmed() {
		if !c.BackportRisk {
			t.Errorf("%s: missing backport flag on an Ubuntu build", c.CVE)
		}
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMatchAgreesWithLookup checks the Matcher fast path against plain lookup and
// filtering, over every product and a spread of versions in the real records.
func TestMatchAgreesWithLookup(t *testing.T) {
	src := loadRealData(t)
	versions := []string{"", "1.0", "1.0.1f", "2.4.49", "6.2", "8.2", "8.2p1", "8.5p1", "9.1p1", "9.3p1", "9.3p2", "9.8", "9.8p1",
		"12.2.1.3.0", "1.20.0", "1.3.5", "1.3.5a", "9.11.4", "9.11.4-s1", "9.18.24", "9.20.10-s1", "7.1p1", "7.1p2",
		"3.7.1p2", "9.16.41-s1", "9.16.42-s1", "9.18.15s1", "22.1", "8.1.1"}
	for product, vendors := range src.byProduct {
		for vendor := range vendors {
			p := Product{Vendor: vendor, Product: product}
			for _, v := range versions {
				var want []string
				for _, e := range src.Lookup(p) {
					if _, ok := matchEntry(e, v); ok {
						want = append(want, e.CVE+"|"+e.ExactVersion+e.StartIncluding+e.EndExcluding+e.EndIncluding)
					}
				}
				var got []string
				for _, e := range src.Match(p, v) {
					got = append(got, e.CVE+"|"+e.ExactVersion+e.StartIncluding+e.EndExcluding+e.EndIncluding)
				}
				sort.Strings(want)
				sort.Strings(got)
				if !equal(got, want) {
					t.Fatalf("%v @ %q: Match %v, Lookup+filter %v", p, v, got, want)
				}
			}
		}
	}
}

func TestRealDataPlatformConditional(t *testing.T) {
	src := loadRealData(t)
	// OS unknown: the Windows-only PHP-CGI CVE stays a lead, marked conditional.
	res := CorrelateResult(Observation{Product: "PHP", Version: "8.1.2"}, src)
	var found bool
	for _, c := range res.Confirmed() {
		if c.CVE == "CVE-2024-4577" {
			found = true
			if c.Platforms != PlatformWindows {
				t.Errorf("platforms = %v", c.Platforms.Names())
			}
		}
	}
	if !found {
		t.Fatal("CVE-2024-4577 missing for an unknown OS")
	}
}

// TestRealDataSpecificLeads checks single CVEs that a fix must include or exclude,
// independent of the other records the version also matches.
func TestRealDataSpecificLeads(t *testing.T) {
	src := loadRealData(t)
	cases := []struct {
		name string
		cpe  string
		cve  string
		want bool
	}{
		// "*:s1 [9.18.11, 9.18.24)" must not stretch past the 9.18.24 fix release.
		{"bind 9.18.24 fixed", "cpe:/a:isc:bind:9.18.24", "CVE-2023-50868", false},
		{"bind 9.18.23", "cpe:/a:isc:bind:9.18.23", "CVE-2023-50868", true},
		// "*:rc2 <= 1.3.2" must not reach the 1.3.2a-e patch releases.
		{"proftpd 1.3.2e", "cpe:/a:proftpd:proftpd:1.3.2e", "CVE-2008-7265", false},
		{"proftpd 1.3.1", "cpe:/a:proftpd:proftpd:1.3.1", "CVE-2008-7265", true},
		// CVE-2006-5051 is "before 4.4" filed as "<= 4.4": 4.4p1 is the fix.
		{"openssh 4.4p1 fixed", "cpe:/a:openbsd:openssh:4.4p1", "CVE-2006-5051", false},
		{"openssh 4.3p2", "cpe:/a:openbsd:openssh:4.3p2", "CVE-2006-5051", true},
		// "*:p2 <= 7.2" still reaches 7.2p2.
		{"openssh 7.2p2", "cpe:/a:openbsd:openssh:7.2p2", "CVE-2016-6210", true},
		{"openssh 7.3p1", "cpe:/a:openbsd:openssh:7.3p1", "CVE-2016-6210", false},
	}
	for _, c := range cases {
		res := CorrelateResult(Observation{CPEs: []string{c.cpe}}, src)
		if got := contains(res.Confirmed(), c.cve); got != c.want {
			t.Errorf("%s: %s confirmed=%v, want %v (%v)", c.name, c.cve, got, c.want, confirmedIDs(res))
		}
	}
}

// TestRealDataUpdateAnyPins covers NVD pins whose update is ANY. For OpenSSH
// "8.2:*" means release 8.2, whose portable build 8.2p1 is what Linux sshd
// reports; a pin with update NA ("9.3:-") is the bare release only. Other
// products keep exact pins: ProFTPD's "1.3.5:*" (CVE-2015-3306) is fixed in
// 1.3.5a.
func TestRealDataUpdateAnyPins(t *testing.T) {
	src := loadRealData(t)
	has := func(obs Observation, cve string) (Candidate, bool) {
		for _, c := range CorrelateResult(obs, src).Confirmed() {
			if c.CVE == cve {
				return c, true
			}
		}
		return Candidate{}, false
	}
	ssh := func(v string) Observation { return Observation{CPEs: []string{"cpe:/a:openbsd:openssh:" + v}} }
	cases := []struct {
		obs  Observation
		cve  string
		want bool
	}{
		{ssh("8.2p1"), "CVE-2020-12062", true},
		{ssh("8.2"), "CVE-2020-12062", true},
		{ssh("8.3p1"), "CVE-2020-12062", false},
		{ssh("8.1p1"), "CVE-2020-12062", false},
		{ssh("9.1p1"), "CVE-2023-25136", true},
		// The CVE pins 7.1:* beside 7.1:p1 and is fixed in 7.1p2: there "*" is
		// the bare release.
		{ssh("7.1"), "CVE-2016-0777", true},
		{ssh("7.1p1"), "CVE-2016-0777", true},
		{ssh("7.1p2"), "CVE-2016-0777", false},
		{ssh("3.7.1p1"), "CVE-2003-0787", true},
		{ssh("3.7.1p2"), "CVE-2003-0787", false},
		// 5.8:* beside 5.8:p1 is not the CVE's last release: every 5.8 build.
		{ssh("5.8p1"), "CVE-2016-0777", true},
		{ssh("5.8p2"), "CVE-2016-0777", true},
		// Errata: "before 5.8p2" filed "<= 5.8"; "before 2.9.9" with 2.9.9 pinned.
		{ssh("5.8"), "CVE-2011-4327", true},
		{ssh("5.8p1"), "CVE-2011-4327", true},
		{ssh("5.8p2"), "CVE-2011-4327", false},
		{ssh("2.9p2"), "CVE-2002-0575", true},
		{ssh("2.9.9"), "CVE-2002-0575", false},
		{ssh("2.9.9p1"), "CVE-2002-0575", false},
		{ssh("9.2p1"), "CVE-2023-25136", false},
		{ssh("9.3p1"), "CVE-2023-38408", true}, // pinned 9.3:p1
		{ssh("9.3p2"), "CVE-2023-38408", false},
		{Observation{CPEs: []string{"cpe:/a:proftpd:proftpd:1.3.5"}}, "CVE-2015-3306", true},
		{Observation{CPEs: []string{"cpe:/a:proftpd:proftpd:1.3.5a"}}, "CVE-2015-3306", false},
		{Observation{CPEs: []string{"cpe:/a:proftpd:proftpd:1.3.5b"}}, "CVE-2015-3306", false},
	}
	for _, c := range cases {
		cand, got := has(c.obs, c.cve)
		if got != c.want {
			t.Errorf("%v: %s matched = %v, want %v", c.obs.CPEs, c.cve, got, c.want)
		}
		if got && c.cve == "CVE-2020-12062" && c.obs.CPEs[0] == ssh("8.2p1").CPEs[0] && cand.MatchBasis != "8.2p1 is a portable build of 8.2" {
			t.Errorf("basis = %q", cand.MatchBasis)
		}
	}
}

// TestRealDataEditionLimited covers BIND records NVD limits to the Supported
// Preview edition (sw_edition "supported_preview"), whose builds report
// "9.11.4-S1": CVE-2026-10723 covers that edition from 9.11.3 but the
// open-source edition only from 9.18.0.
func TestRealDataEditionLimited(t *testing.T) {
	src := loadRealData(t)
	bind := func(v string) Observation {
		return Observation{CPEs: []string{"cpe:/a:isc:bind:" + v}, Product: "ISC BIND", Version: v}
	}
	cases := []struct {
		obs  Observation
		want bool
	}{
		{bind("9.11.4"), false},
		{bind("9.11.4-S1"), true},
		{Observation{CPEs: []string{"cpe:/a:isc:bind:9.11.4:s1"}}, true},
		{bind("9.16.48"), false},
		{bind("9.18.24"), true},
		{bind("9.20.10-S1"), true},
		{bind("9.18.51"), false},
		{Observation{Product: "ISC BIND", Version: "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.13"}, false},
	}
	matched := func(obs Observation, cve string) bool {
		for _, cand := range CorrelateResult(obs, src).Confirmed() {
			if cand.CVE == cve {
				return true
			}
		}
		return false
	}
	for _, c := range cases {
		if got := matched(c.obs, "CVE-2026-10723"); got != c.want {
			t.Errorf("bind %s %v: CVE-2026-10723 matched = %v, want %v", c.obs.Version, c.obs.CPEs, got, c.want)
		}
	}
	// "9.16.8-S1 through 9.16.41-S1" is filed with bare bounds: the edition
	// build of the last release is inside, the next release is not.
	for v, want := range map[string]bool{"9.16.41-S1": true, "9.16.8-S1": true, "9.16.42-S1": false, "9.16.7-S1": false,
		"9.16.41": false, "9.18.15-S1": true, "9.18.16-S1": false} {
		if got := matched(bind(v), "CVE-2023-2829"); got != want {
			t.Errorf("bind %s: CVE-2023-2829 matched = %v, want %v", v, got, want)
		}
	}
}

// TestRealDataDistroLimited covers CVE-2026-123158, OpenSSH before 10.6p2 on
// Alpine Linux only (an AND configuration on o:alpinelinux:alpine_linux).
func TestRealDataDistroLimited(t *testing.T) {
	src := loadRealData(t)
	const cve = "CVE-2026-123158"
	find := func(obs Observation) (Candidate, bool) {
		for _, c := range CorrelateResult(obs, src).Confirmed() {
			if c.CVE == cve {
				return c, true
			}
		}
		return Candidate{}, false
	}
	cases := []struct {
		name        string
		obs         Observation
		want        bool
		conditional bool
	}{
		{"ubuntu", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:canonical:ubuntu_linux"}, Version: "8.2p1 Ubuntu 4ubuntu0.5"}, false, false},
		{"debian banner", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.2p1"}, Version: "9.2p1 Debian 2+deb12u3"}, false, false},
		{"rhel", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.7p1", "cpe:/o:redhat:enterprise_linux"}}, false, false},
		{"windows", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.5p1", "cpe:/o:microsoft:windows"}}, false, false},
		{"alpine", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:alpinelinux:alpine_linux"}}, true, false},
		{"linux, distribution unknown", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"}}, true, true},
		{"nothing known", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}}, true, true},
		{"alpine, fixed", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:10.6p2", "cpe:/o:alpinelinux:alpine_linux"}}, false, false},
		// Other spellings of known distributions' OS CPEs.
		{"suse_linux", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:suse:suse_linux"}}, false, false},
		{"fedora_core", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:fedoraproject:fedora_core"}}, false, false},
		{"oracle linux", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:oracle:linux"}}, false, false},
	}
	for _, c := range cases {
		cand, got := find(c.obs)
		if got != c.want {
			t.Errorf("%s: matched = %v, want %v", c.name, got, c.want)
			continue
		}
		if !got {
			continue
		}
		if conditional := cand.Platforms != 0; conditional != c.conditional {
			t.Errorf("%s: platforms = %v, want conditional %v", c.name, cand.Platforms.Names(), c.conditional)
		}
		if c.conditional && (len(cand.Platforms.Names()) != 1 || cand.Platforms.Names()[0] != "alpine") {
			t.Errorf("%s: only on %v, want [alpine]", c.name, cand.Platforms.Names())
		}
	}
}

// TestRealDataDistroRecordKinds covers a record naming a distribution under
// another vendor's CPE (CVE-2015-1565: novell:opensuse) and a CVE with both a
// distribution-limited and a plain configuration (CVE-2007-5795).
func TestRealDataDistroRecordKinds(t *testing.T) {
	src := loadRealData(t)
	find := func(obs Observation, cve string) (Candidate, bool) {
		for _, c := range CorrelateResult(obs, src).Confirmed() {
			if c.CVE == cve {
				return c, true
			}
		}
		return Candidate{}, false
	}
	hitachi := func(os string) Observation {
		return Observation{CPEs: []string{"cpe:/a:hitachi:device_manager:8.1.1", os}}
	}
	for os, want := range map[string]bool{
		"cpe:/o:suse:linux_enterprise_server": true,
		"cpe:/o:redhat:enterprise_linux":      true,
		"cpe:/o:microsoft:windows":            true,
		"cpe:/o:canonical:ubuntu_linux":       false,
		"cpe:/o:apple:mac_os_x":               false,
	} {
		if _, got := find(hitachi(os), "CVE-2015-1565"); got != want {
			t.Errorf("hitachi on %s: matched = %v, want %v", os, got, want)
		}
	}
	for _, os := range []string{"cpe:/o:linux:linux_kernel", "cpe:/o:redhat:enterprise_linux", "cpe:/o:canonical:ubuntu_linux"} {
		c, ok := find(Observation{CPEs: []string{"cpe:/a:gnu:emacs:22.1", os}}, "CVE-2007-5795")
		if !ok || c.Platforms != 0 {
			t.Errorf("emacs on %s: matched = %v, only on %v; want the unconditional record", os, ok, c.Platforms.Names())
		}
	}

	// want: "" dropped, "any" kept unconditional, else kept only on those names.
	cases := []struct {
		app, os, cve, want string
	}{
		// Debian and Ubuntu (spelled o:ubuntu:ubuntu_linux) packaging only.
		{"cpe:/a:postfix:postfix:2.5.5", "cpe:/o:centos:centos", "CVE-2009-2939", ""},
		{"cpe:/a:postfix:postfix:2.5.5", "cpe:/o:alpinelinux:alpine_linux", "CVE-2009-2939", ""},
		{"cpe:/a:postfix:postfix:2.5.5", "cpe:/o:canonical:ubuntu_linux", "CVE-2009-2939", "any"},
		{"cpe:/a:postfix:postfix:2.5.5", "cpe:/o:linux:linux_kernel", "CVE-2009-2939", "debian"},
		// linux_kernel among the platforms: any Linux.
		{"cpe:/a:netapp:storagegrid:11.6.0.1", "cpe:/o:suse:linux_enterprise_server", "CVE-2022-23238", "any"},
		{"cpe:/a:netapp:storagegrid:11.6.0.1", "cpe:/o:alpinelinux:alpine_linux", "CVE-2022-23238", "any"},
		{"cpe:/a:netapp:storagegrid:11.6.0.1", "cpe:/o:microsoft:windows", "CVE-2022-23238", ""},
		// "x_server on RHEL", while the CVE also marks Debian 11 vulnerable.
		{"cpe:/a:x.org:x_server:1.20.4", "cpe:/o:debian:debian_linux", "CVE-2022-46340", "any"},
		{"cpe:/a:x.org:x_server:1.20.4", "cpe:/o:redhat:enterprise_linux", "CVE-2022-46340", "any"},
		{"cpe:/a:x.org:x_server:1.20.4", "cpe:/o:alpinelinux:alpine_linux", "CVE-2022-46340", ""},
		{"cpe:/a:x.org:x_server:1.20.4", "cpe:/o:linux:linux_kernel", "CVE-2022-46340", "debian/redhat"},
		{"cpe:/a:x.org:x_server:1.20.4", "cpe:/o:microsoft:windows", "CVE-2022-46340", ""},
	}
	for _, c := range cases {
		cand, ok := find(Observation{CPEs: []string{c.app, c.os}}, c.cve)
		got := ""
		switch {
		case !ok:
		case cand.Platforms == 0:
			got = "any"
		default:
			got = strings.Join(cand.Platforms.Names(), "/")
		}
		if got != c.want {
			t.Errorf("%s on %s: %s = %q, want %q", c.app, c.os, c.cve, got, c.want)
		}
	}

	// httpx joins every technology name into the banner text: a JS library named
	// Alpine.js is no distribution, and Win64 says Windows (CVE-2024-4577 is PHP-CGI
	// on Windows only).
	xampp := Observation{Product: "PHP", Version: "8.2.12",
		Extra: "Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12 PHP:8.2.12 Apache HTTP Server:2.4.58 Windows Server Alpine.js:3.13.3"}
	if c, ok := find(xampp, "CVE-2024-4577"); !ok || c.Platforms != 0 {
		t.Errorf("xampp: CVE-2024-4577 matched = %v, only on %v; want unconditional", ok, c.Platforms.Names())
	}
}

func TestDistroFromOSCPE(t *testing.T) {
	for in, want := range map[string]string{
		"cpe:/o:canonical:ubuntu_linux":                 "ubuntu",
		"cpe:/o:suse:suse_linux":                        "suse",
		"cpe:/o:novell:opensuse":                        "suse",
		"cpe:/o:fedoraproject:fedora_core":              "fedora",
		"cpe:/o:redhat:enterprise_linux_server":         "rhel",
		"cpe:/o:oracle:linux":                           "oracle",
		"cpe:2.3:o:rocky:rocky_linux:9.0:*:*:*:*:*:*:*": "rocky",
		"cpe:/o:amazon:linux_2":                         "amazon",
		"cpe:/o:linux:linux_kernel":                     "",
		"cpe:/o:microsoft:windows":                      "",
	} {
		c, _ := ParseCPEName(in)
		if got := distroFromOSCPE(c); got != want {
			t.Errorf("%s: distro %q, want %q", in, got, want)
		}
		if got := distroFromOSCPE(c); got != "" && distroLineage(got) == 0 {
			t.Errorf("%s: distro %q has no lineage", in, got)
		}
	}
}
