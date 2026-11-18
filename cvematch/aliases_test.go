package cvematch

import (
	"regexp"
	"testing"
)

func keys(ps []Product) map[string]bool {
	m := map[string]bool{}
	for _, p := range ps {
		m[p.String()] = true
	}
	return m
}

func TestAliasTableIntegrity(t *testing.T) {
	pairRe := regexp.MustCompile(`^[a-z0-9._!/%+-]+$`)
	names := map[string]int{}
	cpes := map[string]int{}
	for i, tb := range aliasData {
		if len(tb.pairs) == 0 {
			t.Errorf("entry %d has no NVD pair", i)
		}
		for _, p := range append(append([]Product(nil), tb.pairs...), tb.stale...) {
			if !pairRe.MatchString(p.Vendor) || !pairRe.MatchString(p.Product) {
				t.Errorf("entry %d: malformed pair %q", i, p.String())
			}
			if j, dup := cpes[p.key()]; dup && j != i {
				t.Errorf("pair %s is claimed by entries %d and %d", p, j, i)
			}
			cpes[p.key()] = i
		}
		for _, n := range tb.names {
			k := aliasKey(n)
			if k == "" {
				t.Errorf("entry %d: empty alias name %q", i, n)
			}
			if j, dup := names[k]; dup && j != i {
				t.Errorf("name %q is claimed by entries %d and %d", n, j, i)
			}
			names[k] = i
		}
	}
	if len(aliasData) < 90 {
		t.Errorf("alias table shrank to %d entries", len(aliasData))
	}
}

func TestCanonicalRenames(t *testing.T) {
	// nmap's out-of-date nginx vendor reaches every pair NVD files nginx under,
	// including nginx_open_source, used by recent CVEs.
	got := keys(Canonical(Product{Vendor: "igor_sysoev", Product: "nginx"}))
	for _, want := range []string{"f5:nginx", "f5:nginx_open_source", "nginx:nginx"} {
		if !got[want] {
			t.Errorf("igor_sysoev:nginx misses %s: %v", want, got)
		}
	}
	// A current pair also reaches its siblings.
	if got := keys(Canonical(Product{Vendor: "nginx", Product: "nginx"})); !got["f5:nginx_open_source"] {
		t.Errorf("nginx:nginx misses f5:nginx_open_source: %v", got)
	}
	if got := keys(Canonical(Product{Vendor: "vsftpd", Product: "vsftpd"})); !got["vsftpd_project:vsftpd"] || !got["beasts:vsftpd"] {
		t.Errorf("vsftpd: %v", got)
	}
	// An unknown pair maps to itself.
	if got := Canonical(Product{Vendor: "x", Product: "y"}); len(got) != 1 || got[0].String() != "x:y" {
		t.Errorf("unknown pair: %v", got)
	}
}

func TestAliasNames(t *testing.T) {
	cases := map[string]string{
		"Microsoft-IIS":             "microsoft:internet_information_services",
		"Microsoft IIS httpd":       "microsoft:internet_information_server",
		"Apache httpd":              "apache:http_server",
		"Apache HTTP Server":        "apache:http_server",
		"Nginx":                     "f5:nginx",
		"Node.js":                   "nodejs:node.js",
		"Exim smtpd":                "exim:exim",
		"PostgreSQL DB":             "postgresql:postgresql",
		"Redis key-value store":     "redis:redis",
		"Node.js Express framework": "openjsf:express",
	}
	for name, want := range cases {
		if got := keys(AliasProducts(name)); !got[want] {
			t.Errorf("AliasProducts(%q) = %v, want it to include %s", name, got, want)
		}
	}
	// Ambiguous names were rejected on purpose: a bare "Apache" is often a
	// hardened Tomcat, "LiteSpeed" is also OpenLiteSpeed, "MiniServ" is not only
	// Webmin.
	for _, name := range []string{"Apache", "LiteSpeed", "MiniServ", "WebLogic", "nonexistent product"} {
		if got := AliasProducts(name); got != nil {
			t.Errorf("AliasProducts(%q) = %v, want nil", name, got)
		}
	}
	// ASP.NET reports the CLR version (4.0.30319 for every .NET 4.x), which must
	// not be matched against .NET Framework ranges.
	if got := keys(AliasProducts("ASP.NET")); got["microsoft:.net_framework"] {
		t.Error("ASP.NET must not map to .net_framework")
	}
}
