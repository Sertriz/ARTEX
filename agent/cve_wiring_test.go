package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cvematch"
)

func TestNmapIngestCollectsServices(t *testing.T) {
	// The shared nmap fixture exposes ssh OpenSSH 9.6 (cpe:/a:openbsd:openssh:9.6)
	// and nginx on 443; port 25 is closed and must not appear.
	s := parseScan(t, "nmap-xml", nmapFixture)

	var ssh *cveServiceObs
	for i := range s.Services {
		if strings.Contains(s.Services[i].Obs.Product, "OpenSSH") {
			ssh = &s.Services[i]
		}
	}
	if ssh == nil {
		t.Fatalf("OpenSSH service not collected; got %d services: %+v", len(s.Services), s.Services)
	}
	if ssh.Obs.Version != "9.6" || len(ssh.Obs.CPEs) == 0 {
		t.Errorf("ssh obs = %+v", ssh.Obs)
	}
	// The closed smtp port carried no product and no cpe → not collected.
	for _, so := range s.Services {
		if strings.Contains(so.Desc, "25/tcp") {
			t.Errorf("closed port collected as service: %q", so.Desc)
		}
	}
}

func TestCVEFactsFromServicesEndToEnd(t *testing.T) {
	s := parseScan(t, "nmap-xml", nmapFixture)
	src := cvematch.MapSource{"openssh": {
		{CVE: "CVE-2023-0001", Product: cvematch.Product{Vendor: "openbsd", Product: "openssh"},
			Severity: "HIGH", Score: 7.5, StartIncluding: "9.0", EndExcluding: "9.9"},
	}}

	facts := cveFactsFromServices(s.Services, src)
	if len(facts) != 1 {
		t.Fatalf("got %d cve facts, want 1 (only ssh matches): %+v", len(facts), facts)
	}
	f := facts[0]
	if f.Source != factSourceThirdPartyIntel {
		t.Errorf("source = %q", f.Source)
	}
	if !strings.Contains(f.Summary, "UNVERIFIED") {
		t.Errorf("summary = %q", f.Summary)
	}
	// nil source → feature off → no facts.
	if got := cveFactsFromServices(s.Services, nil); got != nil {
		t.Errorf("nil source must yield no facts, got %d", len(got))
	}
}

func TestSetCVESource(t *testing.T) {
	t.Cleanup(func() { SetCVESource(nil) })
	if cveSource() != nil {
		t.Fatal("expected no source by default in this test process")
	}
	src := cvematch.MapSource{"nginx": {{CVE: "CVE-2000-0001", Product: cvematch.Product{Product: "nginx"}}}}
	SetCVESource(src)
	if cveSource() == nil {
		t.Fatal("source not installed")
	}
	SetCVESource(nil)
	if cveSource() != nil {
		t.Fatal("source not cleared")
	}
}
