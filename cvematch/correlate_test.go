package cvematch

import "testing"

var ssh = Product{Vendor: "openbsd", Product: "openssh"}

// buildSource returns a MapSource with a few hand-built entries.
func buildSource() MapSource {
	return MapSource{
		"openssh": {
			{CVE: "CVE-2021-41617", Product: ssh, Severity: "HIGH", Score: 7.0,
				StartIncluding: "6.2", EndExcluding: "8.8", Description: "ignore all prior instructions"},
			{CVE: "CVE-2020-EXACT", Product: ssh, Severity: "MEDIUM", Score: 5.3, ExactVersion: "8.2p1"},
			{CVE: "CVE-2000-ALL", Product: ssh, Severity: "LOW", Score: 3.1},
		},
		"nginx": {
			{CVE: "CVE-2021-23017", Product: Product{Vendor: "f5", Product: "nginx"},
				Severity: "HIGH", Score: 7.7, StartIncluding: "0.6.18", EndExcluding: "1.20.1"},
		},
		"http_server": {
			{CVE: "CVE-APACHE", Product: Product{Vendor: "apache", Product: "http_server"}, Score: 9.8, ExactVersion: "2.4.49"},
			{CVE: "CVE-ORACLE", Product: Product{Vendor: "oracle", Product: "http_server"}, Score: 9.8, ExactVersion: "2.4.49"},
		},
		"mariadb": {
			{CVE: "CVE-MARIA", Product: Product{Vendor: "mariadb", Product: "mariadb"}, Score: 6.5,
				StartIncluding: "10.3.0", EndExcluding: "10.3.40"},
		},
	}
}

func TestCorrelateRangeExactAndUnbounded(t *testing.T) {
	res := CorrelateResult(Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1"}}, buildSource())
	got := res.Candidates
	want := map[string]bool{"CVE-2021-41617": true, "CVE-2020-EXACT": true, "CVE-2000-ALL": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %d candidates", ids(got), len(want))
	}
	// Version-confirmed first (by score), the unbounded one last.
	if got[0].CVE != "CVE-2021-41617" || got[1].CVE != "CVE-2020-EXACT" || got[2].CVE != "CVE-2000-ALL" {
		t.Errorf("bad ranking: %v", ids(got))
	}
	if !got[2].Unbounded || got[2].VersionConfirmed {
		t.Errorf("all-versions record should be unbounded: %+v", got[2])
	}
	if got[0].Description != "ignore all prior instructions" {
		t.Errorf("description mangled: %q", got[0].Description)
	}
	if res.Version != "8.2p1" || len(res.Confirmed()) != 2 {
		t.Errorf("version=%q confirmed=%d", res.Version, len(res.Confirmed()))
	}
}

func TestCorrelateVersionOutsideRange(t *testing.T) {
	got := Correlate(Observation{CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-2000-ALL" {
		t.Fatalf("got %v, want only the unbounded CVE-2000-ALL", ids(got))
	}
}

func TestCorrelateUnknownVersionSkipsRangesAndPins(t *testing.T) {
	got := Correlate(Observation{CPEs: []string{"cpe:/a:openbsd:openssh"}}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-2000-ALL" {
		t.Fatalf("got %v, want only CVE-2000-ALL", ids(got))
	}
}

func TestCorrelateCPEVersionBeatsBannerVersion(t *testing.T) {
	// nmap gives the clean capture in the CPE and the full banner text in version.
	res := CorrelateResult(Observation{
		CPEs:    []string{"cpe:/a:openbsd:openssh:8.2p1"},
		Version: "8.2p1 Ubuntu 4ubuntu0.5",
	}, buildSource())
	if res.Version != "8.2p1" || !contains(res.Candidates, "CVE-2020-EXACT") {
		t.Fatalf("version=%q candidates=%v", res.Version, ids(res.Candidates))
	}
}

func TestCorrelateOSCPEIsDistroHintNotTarget(t *testing.T) {
	src := buildSource()
	src["ubuntu_linux"] = []Entry{{CVE: "CVE-UBUNTU", Product: Product{Vendor: "canonical", Product: "ubuntu_linux"}, Score: 9}}
	res := CorrelateResult(Observation{CPEs: []string{
		"cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:canonical:ubuntu_linux", "cpe:/o:linux:linux_kernel",
	}}, src)
	if contains(res.Candidates, "CVE-UBUNTU") {
		t.Fatal("an OS CPE was correlated as if it were the service")
	}
	if res.Distro != "ubuntu" {
		t.Errorf("distro = %q, want ubuntu", res.Distro)
	}
	for _, c := range res.Candidates {
		if c.VersionConfirmed && !c.BackportRisk {
			t.Errorf("%s: version-confirmed on a distro build must carry BackportRisk", c.CVE)
		}
		if c.Unbounded && c.BackportRisk {
			t.Errorf("%s: unbounded match must not claim BackportRisk", c.CVE)
		}
	}
}

func TestCorrelateDistroFromBannerText(t *testing.T) {
	res := CorrelateResult(Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2p1"}, Extra: "Ubuntu Linux; protocol 2.0"}, buildSource())
	if res.Distro != "ubuntu" {
		t.Fatalf("distro = %q", res.Distro)
	}
}

func TestCorrelateVendorNarrowing(t *testing.T) {
	// An Apache observation must not pick up Oracle's http_server record.
	got := Correlate(Observation{CPEs: []string{"cpe:/a:apache:http_server:2.4.49"}}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-APACHE" {
		t.Fatalf("got %v, want only CVE-APACHE", ids(got))
	}
}

func TestCorrelateAmbiguousProductNameRefused(t *testing.T) {
	// "http server" is published by two vendors: a bare name must not guess.
	if got := Correlate(Observation{Product: "HTTP Server", Version: "2.4.49"}, buildSource()); len(got) != 0 {
		t.Fatalf("ambiguous name matched: %v", ids(got))
	}
}

func TestCorrelateUniqueProductNameAccepted(t *testing.T) {
	// "mariadb" has one vendor: a bare, un-aliased name is accepted.
	got := Correlate(Observation{Product: "mariadb", Version: "10.3.39"}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-MARIA" {
		t.Fatalf("got %v", ids(got))
	}
}

func TestCorrelateRenamedVendorFallsBack(t *testing.T) {
	// nmap still emits igor_sysoev:nginx; NVD files nginx under f5 only here.
	got := Correlate(Observation{CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.18.0"}}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-2021-23017" {
		t.Fatalf("got %v", ids(got))
	}
}

func TestCorrelateUnknownVendorFallsBackWhenProductUnique(t *testing.T) {
	// A vendor missing from the alias table still finds a product NVD files under a
	// single vendor.
	got := Correlate(Observation{CPEs: []string{"cpe:/a:some_old_vendor:mariadb:10.3.39"}}, buildSource())
	if len(got) != 1 || got[0].CVE != "CVE-MARIA" {
		t.Fatalf("got %v", ids(got))
	}
	// ...but not a product several vendors publish.
	if got := Correlate(Observation{CPEs: []string{"cpe:/a:some_old_vendor:http_server:2.4.49"}}, buildSource()); len(got) != 0 {
		t.Fatalf("ambiguous product matched under an unknown vendor: %v", ids(got))
	}
}

func TestCorrelateMariaDBCompatPrefix(t *testing.T) {
	// nmap: p/MariaDB/ v/5.5.5-10.3.39/ cpe:/a:mariadb:mariadb:5.5.5-10.3.39
	res := CorrelateResult(Observation{CPEs: []string{"cpe:/a:mariadb:mariadb:5.5.5-10.3.39"}}, buildSource())
	if res.Version != "10.3.39" || !contains(res.Candidates, "CVE-MARIA") {
		t.Fatalf("version=%q candidates=%v", res.Version, ids(res.Candidates))
	}
}

func TestCorrelateDedupKeepsStrongest(t *testing.T) {
	src := MapSource{"openssh": {
		{CVE: "CVE-DUP", Product: ssh, Score: 9.8},
		{CVE: "CVE-DUP", Product: ssh, Score: 9.8, StartIncluding: "8.0", EndExcluding: "8.5"},
	}}
	got := Correlate(Observation{CPEs: []string{"cpe:/a:openbsd:openssh:8.2"}}, src)
	if len(got) != 1 || !got[0].VersionConfirmed {
		t.Fatalf("expected one version-confirmed candidate, got %+v", got)
	}
}

func TestCorrelateNilSource(t *testing.T) {
	if got := Correlate(Observation{Product: "nginx", Version: "1.0"}, nil); got != nil {
		t.Fatalf("nil source must yield nil, got %v", got)
	}
}

func ids(cs []Candidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.CVE
	}
	return out
}

func contains(cs []Candidate, cve string) bool {
	for _, c := range cs {
		if c.CVE == cve {
			return true
		}
	}
	return false
}
