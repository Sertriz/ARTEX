package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/cvematch"
)

// An nmap -sV fixture shaped like real output: OpenSSH on Ubuntu (nmap's CPE
// carries the clean version, the version attribute the distro text), vsftpd with
// nmap's out-of-date vendor, nginx with nmap's out-of-date vendor, a closed port,
// and a service with no product.
const nmapCVEFixture = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 198.51.100.0/24" version="7.94">
<host><status state="up"/><address addr="198.51.100.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:canonical:ubuntu_linux</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4" ostype="Unix"><cpe>cpe:/a:vsftpd:vsftpd:2.3.4</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
<port protocol="tcp" portid="25"><state state="closed"/><service name="smtp" product="Exim smtpd" version="4.92"/></port>
<port protocol="tcp" portid="111"><state state="open"/><service name="rpcbind"/></port>
</ports></host>
<host><status state="up"/><address addr="198.51.100.11" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:canonical:ubuntu_linux</cpe></service></port>
</ports></host>
</nmaprun>
`

const httpxCVEFixture = `{"url":"https://203.0.113.5:8443/admin?token=secret","status_code":200,"title":"x","tech":["Nginx:1.18.0","PHP:7.4.3","jQuery","Ubuntu"],"webserver":"nginx/1.18.0 (Ubuntu)","host":"203.0.113.5","ip":"203.0.113.5"}
{"url":"http://198.51.100.20/","status_code":200,"tech":["Apache HTTP Server:2.4.49"],"webserver":"Apache/2.4.49 (Unix) OpenSSL/1.0.1f","ip":"198.51.100.20"}
`

func TestNmapIngestCollectsServices(t *testing.T) {
	s := parseScan(t, "nmap-xml", nmapCVEFixture)
	if len(s.Services) != 4 {
		t.Fatalf("got %d services, want 4 (ssh, ftp, http, ssh): %+v", len(s.Services), s.Services)
	}
	ssh := s.Services[0]
	if ssh.Target != "198.51.100.10:22/tcp" {
		t.Errorf("target = %q", ssh.Target)
	}
	if a := s.Assets[ssh.AssetIdx]; a.Type != "service" || a.Port != 22 || a.IP != "198.51.100.10" {
		t.Errorf("asset index %d points at %+v, want the port-22 service", ssh.AssetIdx, a)
	}
	if !strings.Contains(ssh.Obs.Extra, "Ubuntu Linux") || len(ssh.Obs.CPEs) != 3 {
		t.Errorf("obs = %+v", ssh.Obs)
	}
	// The http service's asset is the URL service.
	if web := s.Services[2]; s.Assets[web.AssetIdx].URL != "http://198.51.100.10:80" {
		t.Errorf("web asset = %+v", s.Assets[web.AssetIdx])
	}
	for _, so := range s.Services {
		if strings.Contains(so.Target, ":25/") || strings.Contains(so.Target, ":111/") {
			t.Errorf("closed or product-less port collected: %q", so.Target)
		}
	}
}

func TestHttpxIngestCollectsServices(t *testing.T) {
	s := parseScan(t, "httpx-jsonl", httpxCVEFixture)
	var got []string
	for _, so := range s.Services {
		got = append(got, so.Target+" "+so.Obs.Product+" "+so.Obs.Version)
		if s.Assets[so.AssetIdx].Type != "service" {
			t.Errorf("asset index %d is not the httpx service", so.AssetIdx)
		}
	}
	want := []string{
		"https://203.0.113.5:8443 Nginx 1.18.0", // the header's nginx/1.18.0 is the same product+version
		"https://203.0.113.5:8443 PHP 7.4.3",
		"http://198.51.100.20 Apache HTTP Server 2.4.49",
		"http://198.51.100.20 Apache 2.4.49",
		"http://198.51.100.20 OpenSSL 1.0.1f",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("services\n got: %q\nwant: %q", got, want)
	}
	if !strings.Contains(s.Services[0].Obs.Extra, "(Ubuntu)") {
		t.Errorf("distro hint missing: %q", s.Services[0].Obs.Extra)
	}
}

func TestHTTPTarget(t *testing.T) {
	cases := map[string]string{
		"https://203.0.113.5:8443/admin?token=secret#x": "https://203.0.113.5:8443",
		"http://Example.COM/":                           "http://example.com",
		"http://[2001:db8::1]:8080/":                    "http://[2001:db8::1]:8080",
		"http://bad host/":                              "",
		"http://example.com:99999/":                     "",
	}
	for in, want := range cases {
		if got := httpTarget(in); got != want {
			t.Errorf("httpTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCVEWiringEndToEnd runs scanner output through the parser and the
// correlator against the real NVD records in cvematch/testdata/nvd.
func TestCVEWiringEndToEnd(t *testing.T) {
	src, err := cvematch.LoadNVDDir("../cvematch/testdata/nvd")
	if err != nil {
		t.Fatal(err)
	}
	s := parseScan(t, "nmap-xml", nmapCVEFixture)
	ids := map[int]int64{}
	for i := range s.Assets {
		ids[i] = int64(1000 + i)
	}
	facts, st := cveFactsFromServices(context.Background(), s.Services, src, ids, "nmap-xml")
	if len(facts) != 3 || st.Matched != 4 {
		t.Fatalf("got %d facts (stats %+v):\n%s", len(facts), st, summaries(facts))
	}
	expect := []string{
		// Both Ubuntu hosts run the same OpenSSH build: one fact, two anchors.
		"CVE lead (unverified): openbsd:openssh 8.2p1 — CVE-2023-38408, CVE-2021-41617 +1 (1 critical, 1 high); ubuntu build, fixes may be backported; on 198.51.100.10:22/tcp +1 more",
		"CVE lead (unverified): vsftpd_project:vsftpd 2.3.4 — CVE-2011-2523 (1 critical, 0 high); on 198.51.100.10:21/tcp",
		"CVE lead (unverified): f5:nginx 1.18.0 — CVE-2021-23017",
	}
	for i, want := range expect {
		if !strings.HasPrefix(facts[i].Summary, want) {
			t.Errorf("fact %d\n got: %s\nwant prefix: %s", i, facts[i].Summary, want)
		}
	}
	if len(facts[0].AssetIDs) != 2 {
		t.Errorf("openssh fact anchors = %s", facts[0].AssetIDs)
	}

	hs := parseScan(t, "httpx-jsonl", httpxCVEFixture)
	hf, _ := cveFactsFromServices(context.Background(), hs.Services, src, nil, "httpx-jsonl")
	joined := summaries(hf)
	for _, want := range []string{"f5:nginx 1.18.0 — CVE-2021-23017", "on https://203.0.113.5:8443", "apache:http_server 2.4.49 — CVE-2021-41773", "openssl:openssl 1.0.1f — CVE-2014-0160", "on http://198.51.100.20"} {
		if !strings.Contains(joined, want) {
			t.Errorf("httpx facts missing %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "token=secret") || strings.Contains(joined, "/admin") {
		t.Error("URL path or query leaked into a summary")
	}
}

func summaries(fs []factItem) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Summary + "\n")
	}
	return b.String()
}
