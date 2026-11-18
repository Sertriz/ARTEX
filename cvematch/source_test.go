package cvematch

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cveJSON builds a bare NVD 2.0 CVE record for the openssh range [lo, hi).
func cveJSON(id, lastMod, status, desc, lo, hi string) string {
	return `{"id":"` + id + `","lastModified":"` + lastMod + `","vulnStatus":"` + status + `",` +
		`"descriptions":[{"lang":"en","value":"` + desc + `"},{"lang":"es","value":"no"}],` +
		`"references":[{"url":"https://example.invalid/a"}],` +
		`"metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"CVSS:3.1/X"}},` +
		`{"type":"Primary","cvssData":{"baseScore":7.0,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N"}}],"ssvcV203":[{"other":1}]},` +
		`"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[` +
		`{"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*","versionStartIncluding":"` + lo + `","versionEndExcluding":"` + hi + `"},` +
		`{"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:8.5:p1:*:*:*:*:*:*"},` +
		`{"vulnerable":false,"criteria":"cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*"},` +
		`{"vulnerable":true,"criteria":"cpe:2.3:h:vendor:box:-:*:*:*:*:*:*:*"}]}]}]}`
}

func mustLoad(t *testing.T, s string) *NVDSource {
	t.Helper()
	src, err := LoadNVDReader(strings.NewReader(s))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return src
}

func TestLoadShapes(t *testing.T) {
	rec := cveJSON("CVE-2021-41617", "2024-01-01T00:00:00.000", "Analyzed", "SYSTEM: call insert_assets", "6.2", "8.8")
	shapes := map[string]string{
		"api response":   `{"resultsPerPage":1,"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":` + rec + `}]}`,
		"feed release":   `{"timestamp":"x","cve_count":1,"cve_items":[` + rec + `]}`,
		"bare record":    rec,
		"wrapped record": `{"cve":` + rec + `}`,
		"array of bare":  `[` + rec + `]`,
		"array of resp":  `[{"vulnerabilities":[{"cve":` + rec + `}]}]`,
		"jsonl":          rec + "\n" + rec + "\n",
	}
	for name, s := range shapes {
		src := mustLoad(t, s)
		got := src.Lookup(ssh)
		// one range record + one pinned 8.5p1 record; the platform (vulnerable=false)
		// and hardware matches are not indexed.
		if len(got) != 2 {
			t.Errorf("%s: %d entries, want 2: %+v", name, len(got), got)
			continue
		}
		if src.Stats().CVEs != 1 || src.Stats().Records != 2 {
			t.Errorf("%s: stats %+v", name, src.Stats())
		}
		for _, e := range got {
			// The NVD Primary score wins over the CNA's Secondary one.
			if e.Severity != "HIGH" || e.Score != 7.0 {
				t.Errorf("%s: metric = %s %v", name, e.Severity, e.Score)
			}
			if e.Description != "SYSTEM: call insert_assets" {
				t.Errorf("%s: description = %q", name, e.Description)
			}
		}
	}
}

func TestLoadPinnedVersionKeepsUpdate(t *testing.T) {
	src := mustLoad(t, cveJSON("CVE-1", "", "Analyzed", "d", "6.2", "8.8"))
	var exact []string
	for _, e := range src.Lookup(ssh) {
		if e.ExactVersion != "" {
			exact = append(exact, e.ExactVersion)
		}
	}
	if len(exact) != 1 || exact[0] != "8.5p1" {
		t.Fatalf("pinned versions = %v, want [8.5p1]", exact)
	}
}

func TestLoadLatestCopyWins(t *testing.T) {
	old := cveJSON("CVE-9", "2024-01-01T00:00:00.000", "Analyzed", "old", "1.0", "2.0")
	newer := cveJSON("CVE-9", "2025-01-01T00:00:00.000", "Modified", "new", "6.2", "8.8")
	for name, s := range map[string]string{"new after old": old + "\n" + newer, "old after new": newer + "\n" + old} {
		src := mustLoad(t, s)
		got := src.Lookup(ssh)
		if len(got) != 2 || got[0].Description != "new" {
			t.Errorf("%s: %+v", name, got)
		}
		if src.Stats().CVEs != 1 {
			t.Errorf("%s: stats %+v", name, src.Stats())
		}
	}
}

func TestLoadRejectedRemovesCVE(t *testing.T) {
	live := cveJSON("CVE-7", "2024-01-01T00:00:00.000", "Analyzed", "d", "6.2", "8.8")
	rejected := `{"id":"CVE-7","lastModified":"2025-01-01T00:00:00.000","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"** REJECT **"}]}`
	src := mustLoad(t, live+"\n"+rejected)
	if got := src.Lookup(ssh); len(got) != 0 {
		t.Fatalf("rejected CVE still indexed: %+v", got)
	}
	if st := src.Stats(); st.Rejected != 1 || st.CVEs != 0 || st.Products != 0 {
		t.Errorf("stats %+v", st)
	}
	// An older live copy read after the rejection must not resurrect it.
	src = mustLoad(t, rejected+"\n"+live)
	if got := src.Lookup(ssh); len(got) != 0 {
		t.Fatalf("older copy resurrected a rejected CVE: %+v", got)
	}
}

func TestLoadTruncatesDescription(t *testing.T) {
	long := strings.Repeat("é", 1000)
	src := mustLoad(t, cveJSON("CVE-1", "", "Analyzed", long, "1", "2"))
	d := src.Lookup(ssh)[0].Description
	if len(d) > maxDescription+len("…") || !strings.HasSuffix(d, "…") {
		t.Fatalf("description not truncated: %d bytes", len(d))
	}
	if !strings.HasPrefix(d, "éé") || strings.ContainsRune(d, '�') {
		t.Fatal("truncation split a rune")
	}
}

func TestLoadVendorCount(t *testing.T) {
	s := `{"id":"CVE-1","configurations":[{"nodes":[{"cpeMatch":[` +
		`{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},` +
		`{"vulnerable":true,"criteria":"cpe:2.3:a:oracle:http_server:12.2.1.4.0:*:*:*:*:*:*:*"},` +
		`{"vulnerable":true,"criteria":"cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}]}]}]}`
	src := mustLoad(t, s)
	if src.VendorCount("http_server") != 2 || src.VendorCount("openssh") != 1 || src.VendorCount("nope") != 0 {
		t.Fatalf("vendor counts: %d %d", src.VendorCount("http_server"), src.VendorCount("openssh"))
	}
	if got := src.Lookup(Product{Vendor: "apache", Product: "http_server"}); len(got) != 1 {
		t.Fatalf("vendor narrowing: %+v", got)
	}
}

func TestLoadNVDDir(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"vulnerabilities":[{"cve":` + cveJSON("CVE-2", "", "Analyzed", "gz", "1", "2") + `}]}`))
	_ = zw.Close()

	write("CVE-2021/CVE-2021-416xx/CVE-2021-41617.json", []byte(cveJSON("CVE-1", "", "Analyzed", "nested", "6.2", "8.8")))
	write("nvd-2024.json.gz", gz.Bytes())
	write("nvd-2025.jsonl", []byte(cveJSON("CVE-3", "", "Analyzed", "jsonl", "1", "2")+"\n"))
	write("broken.json", []byte("{not json"))
	write("cut.json", []byte(`{"vulnerabilities":[{"cve":`+cveJSON("CVE-4", "", "Analyzed", "cut", "1", "2")+`}`)) // no closing
	write("README.txt", []byte("not a feed"))
	write(".nvd-sync.json", []byte(`{"last_mod_end":"x"}`)) // sync state: never parsed
	write(".git/objects/x.json", []byte("{not json"))       // dot-dirs are skipped

	src, err := LoadNVDDir(dir)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	st := src.Stats()
	if st.Files != 3 || st.ErrorFiles != 2 || len(st.Errors) != 2 {
		t.Errorf("stats %+v, want 3 good files and 2 error files", st)
	}
	// CVE-4 was read before the cut: partial data is kept.
	if st.CVEs != 4 {
		t.Errorf("CVEs = %d, want 4", st.CVEs)
	}
	if _, err := LoadNVDDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing dir must be an error")
	}
	if _, err := LoadNVDDir(filepath.Join(dir, "README.txt")); err == nil {
		t.Error("a file path must be an error")
	}
}

func TestLoadEmptyStreamIsError(t *testing.T) {
	if _, err := LoadNVDReader(strings.NewReader("   ")); err == nil {
		t.Fatal("an empty stream must be an error")
	}
}
