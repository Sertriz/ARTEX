package cvematch

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Entry is one affected-configuration record for a CVE: a single CPE match from
// the NVD feed, reduced to the fields correlation needs. One CVE can produce many
// Entries (one per vulnerable cpeMatch).
type Entry struct {
	CVE         string // e.g. "CVE-2020-14145"
	Product     Product
	Severity    string  // CRITICAL|HIGH|MEDIUM|LOW|NONE|"" (CVSS baseSeverity, uppercased)
	Score       float64 // CVSS baseScore; 0 when unknown
	Vector      string  // CVSS vector string, as-is
	Description string  // English description — INERT third-party text, never interpreted

	// Version constraints. ExactVersion is set when the CPE criteria pins a single
	// version and no range bounds are given; otherwise the four range bounds apply
	// (any may be empty). An Entry with neither an exact version nor any bound
	// matches every version of the product ("all versions affected").
	ExactVersion   string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
}

// Source answers "which CVE entries concern this product?". Lookup must be safe
// for concurrent use and must return entries for the given vendor:product key and,
// when the product's vendor is empty, for the product-only key.
type Source interface {
	Lookup(p Product) []Entry
}

// NVDSource is an in-memory index of CVE Entries keyed by product name, built from
// NVD CVE API 2.0 / feed JSON. It is read-only after construction and safe for
// concurrent Lookup.
//
// Keying by product name (not vendor:product) lets a bare product banner such as
// nmap's "OpenSSH" — which carries no reliable vendor — still reach the CVEs,
// while a known vendor narrows the result in Lookup. Each entry keeps its own
// vendor in Entry.Product.
type NVDSource struct {
	byProduct map[string][]Entry // product name (lowercased) -> entries
}

// Lookup returns the entries for p.Product. When p.Vendor is set, entries are
// narrowed to that vendor (plus vendor-less entries, which stay eligible); with no
// vendor, every vendor's entries for that product name are returned. Correlate
// dedups by CVE after version matching, so a product shared by several vendors is
// resolved there.
func (s *NVDSource) Lookup(p Product) []Entry {
	if s == nil || p.Product == "" {
		return nil
	}
	cands := s.byProduct[p.Product]
	if p.Vendor == "" {
		return cands
	}
	var out []Entry
	for _, e := range cands {
		if e.Product.Vendor == p.Vendor || e.Product.Vendor == "" {
			out = append(out, e)
		}
	}
	return out
}

// Len reports how many product keys the index holds (for diagnostics/tests).
func (s *NVDSource) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byProduct)
}

// LoadNVDDir builds an NVDSource from every *.json file in dir (non-recursive).
// Files that fail to decode are skipped and counted in the returned skipped count;
// an unreadable directory is an error. A file may be a single NVD 2.0 response
// object or a JSON array of them.
func LoadNVDDir(dir string) (src *NVDSource, files, skipped int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read cve feed dir: %w", err)
	}
	idx := map[string][]Entry{}
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(strings.ToLower(de.Name()), ".json") {
			continue
		}
		f, e := os.Open(filepath.Join(dir, de.Name()))
		if e != nil {
			skipped++
			continue
		}
		n := indexNVDReader(f, idx)
		f.Close()
		if n < 0 {
			skipped++
			continue
		}
		files++
	}
	return &NVDSource{byProduct: idx}, files, skipped, nil
}

// LoadNVDReader builds an NVDSource from a single reader of NVD 2.0 JSON.
func LoadNVDReader(r io.Reader) (*NVDSource, error) {
	idx := map[string][]Entry{}
	if n := indexNVDReader(r, idx); n < 0 {
		return nil, fmt.Errorf("decode nvd json")
	}
	return &NVDSource{byProduct: idx}, nil
}

// ---- NVD 2.0 JSON shapes (only the fields we read) ----

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Configurations []nvdConfigNode `json:"configurations"`
}

type nvdMetrics struct {
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	// CVSS v2 carries severity as a sibling of cvssData.
	BaseSeverity string `json:"baseSeverity"`
}

type nvdConfigNode struct {
	Nodes []struct {
		CPEMatch []nvdCPEMatch `json:"cpeMatch"`
	} `json:"nodes"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// indexNVDReader decodes NVD 2.0 JSON (a single object or an array of objects)
// from r and adds every vulnerable cpeMatch as an Entry into idx. It returns the
// number of CVEs indexed, or -1 on a decode error.
func indexNVDReader(r io.Reader, idx map[string][]Entry) int {
	data, err := io.ReadAll(r)
	if err != nil {
		return -1
	}
	trimmed := strings.TrimSpace(string(data))
	var responses []nvdResponse
	if strings.HasPrefix(trimmed, "[") {
		if json.Unmarshal(data, &responses) != nil {
			return -1
		}
	} else {
		var one nvdResponse
		if json.Unmarshal(data, &one) != nil {
			return -1
		}
		responses = []nvdResponse{one}
	}

	count := 0
	for _, resp := range responses {
		for _, v := range resp.Vulnerabilities {
			if indexOneCVE(v.CVE, idx) {
				count++
			}
		}
	}
	return count
}

// indexOneCVE adds one CVE's vulnerable cpeMatches to idx. It returns true when at
// least one Entry was produced.
func indexOneCVE(c nvdCVE, idx map[string][]Entry) bool {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		return false
	}
	sev, score, vector := bestMetric(c.Metrics)
	desc := englishDescription(c.Descriptions)

	added := false
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				prod, exact, ok := ParseCPE(m.Criteria)
				if !ok || prod.empty() {
					continue
				}
				e := Entry{
					CVE:            id,
					Product:        prod,
					Severity:       strings.ToUpper(sev),
					Score:          score,
					Vector:         vector,
					Description:    desc,
					StartIncluding: m.VersionStartIncluding,
					StartExcluding: m.VersionStartExcluding,
					EndIncluding:   m.VersionEndIncluding,
					EndExcluding:   m.VersionEndExcluding,
				}
				// An exact version from the criteria only counts when the match
				// carries no range bounds; otherwise the bounds define the set.
				if exact != "" && !e.hasRange() {
					e.ExactVersion = exact
				}
				idx[prod.Product] = append(idx[prod.Product], e)
				added = true
			}
		}
	}
	return added
}

func (e Entry) hasRange() bool {
	return e.StartIncluding != "" || e.StartExcluding != "" ||
		e.EndIncluding != "" || e.EndExcluding != ""
}

// bestMetric picks the preferred CVSS metric: v3.1, then v3.0, then v2.
func bestMetric(m nvdMetrics) (severity string, score float64, vector string) {
	for _, group := range [][]nvdMetric{m.V31, m.V30} {
		if len(group) > 0 {
			d := group[0]
			return d.CVSSData.BaseSeverity, d.CVSSData.BaseScore, d.CVSSData.VectorString
		}
	}
	if len(m.V2) > 0 {
		d := m.V2[0]
		sev := d.BaseSeverity // v2 severity is a sibling of cvssData
		return sev, d.CVSSData.BaseScore, d.CVSSData.VectorString
	}
	return "", 0, ""
}

func englishDescription(ds []struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}) string {
	for _, d := range ds {
		if strings.EqualFold(d.Lang, "en") {
			return strings.TrimSpace(d.Value)
		}
	}
	if len(ds) > 0 {
		return strings.TrimSpace(ds[0].Value)
	}
	return ""
}

// MapSource is a trivial in-memory Source for tests and for callers that build
// entries directly. Keys are product names (lowercased), matching NVDSource.
type MapSource map[string][]Entry

// Lookup implements Source with the same vendor-narrowing as NVDSource.
func (m MapSource) Lookup(p Product) []Entry {
	if p.Product == "" {
		return nil
	}
	cands := m[p.Product]
	if p.Vendor == "" {
		return cands
	}
	var out []Entry
	for _, e := range cands {
		if e.Product.Vendor == p.Vendor || e.Product.Vendor == "" {
			out = append(out, e)
		}
	}
	return out
}
