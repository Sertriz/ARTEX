package cvematch

import (
	"sort"
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
//   - CVE-2024-6387.json.gz: the full, untrimmed regreSSHion record, gzipped.
func loadRealData(t *testing.T) *NVDSource {
	t.Helper()
	src, err := LoadNVDDir("testdata/nvd")
	if err != nil {
		t.Fatalf("load testdata: %v", err)
	}
	if st := src.Stats(); st.Files != 3 || st.ErrorFiles != 0 || st.CVEs != 19 {
		t.Fatalf("testdata stats %+v, want 3 files and 19 CVEs", st)
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
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408"}},
		// regreSSHion: NVD pins 8.5p1 and ranges 8.6..9.8.
		{"openssh 8.5p1 pinned", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.5p1"}},
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408", "CVE-2024-6387"}},
		{"openssh 9.6p1", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}},
			[]string{"CVE-2024-6387"}},
		// 9.8p1 is the regreSSHion fix: outside "<= 9.8".
		{"openssh 9.8p1 fixed", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.8p1"}}, nil},
		// CVE-2023-38408 pins 9.3 and 9.3p1; 9.3p2 is the fix.
		{"openssh 9.3p1 pinned", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.3p1"}},
			[]string{"CVE-2023-38408", "CVE-2024-6387"}},
		{"openssh 9.3p2 fixed for 38408", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.3p2"}},
			[]string{"CVE-2024-6387"}},
		// The bare product name, as httpx or a banner reports it.
		{"OpenSSH by name", Observation{Product: "OpenSSH", Version: "8.2p1"},
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408"}},
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
			[]string{"CVE-2016-20012", "CVE-2018-15473", "CVE-2019-6111", "CVE-2021-41617", "CVE-2023-38408"}},
		// CVE-2016-6210 is filed "openssh:*:p2 <= 7.2": up to 7.2p2.
		{"openssh 7.2p2 (Ubuntu 16.04)", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:7.2p2"}},
			[]string{"CVE-2016-20012", "CVE-2016-6210", "CVE-2018-15473", "CVE-2019-6111", "CVE-2021-41617", "CVE-2023-38408"}},
		{"openssh 8.7p1", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.7p1"}},
			[]string{"CVE-2016-20012", "CVE-2021-41617", "CVE-2023-38408", "CVE-2024-6387"}},
		// regreSSHion's NVD bound "<= 9.8" is an erratum: 9.8 is the fix.
		{"openssh 9.8 openbsd", Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.8"}}, nil},

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
	versions := []string{"", "1.0", "1.0.1f", "2.4.49", "6.2", "8.2p1", "8.5p1", "9.3p1", "9.8", "9.8p1", "12.2.1.3.0", "1.20.0"}
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
