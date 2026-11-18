package cvematch

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Entry is one affected-configuration record for a CVE: a single vulnerable CPE
// match from NVD, reduced to the fields correlation needs. One CVE can produce
// many Entries (one per vulnerable cpeMatch).
type Entry struct {
	CVE         string // e.g. "CVE-2021-41617"
	Product     Product
	Severity    string  // CRITICAL|HIGH|MEDIUM|LOW|NONE|"" (CVSS baseSeverity, uppercased)
	Score       float64 // CVSS baseScore; 0 when unknown
	Vector      string  // CVSS vector string, as-is
	Description string  // English description — INERT third-party text, never interpreted

	// Version constraints. ExactVersion is set when the CPE criteria pins a single
	// (full: version+update) version and no range bounds are given; otherwise the
	// four range bounds apply (any may be empty). An Entry with neither matches
	// every version of the product ("unbounded").
	ExactVersion   string
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string

	// Platforms is set when NVD limits the record to a platform (an AND
	// configuration such as "php:php ... running on o:microsoft:windows").
	Platforms PlatformSet
}

func (e Entry) hasRange() bool {
	return e.StartIncluding != "" || e.StartExcluding != "" ||
		e.EndIncluding != "" || e.EndExcluding != ""
}

// Source answers "which CVE entries concern this product?". Lookup must be safe
// for concurrent use. With a vendor it returns that vendor's entries (plus
// vendor-less ones); with no vendor it returns every vendor's entries for the
// product name.
type Source interface {
	Lookup(p Product) []Entry
}

// Matcher is implemented by sources that can apply version constraints
// themselves: Match returns the entries of p whose pinned version or range holds
// version, plus the unbounded ones (with an empty version, only the unbounded
// ones). Correlate prefers it, since only matching records are materialized; it
// still re-checks every entry, so Match is an optimization, never a decision.
type Matcher interface {
	Match(p Product, version string) []Entry
}

// VendorCounter is implemented by sources that can say how many distinct vendors
// publish a product name. Correlate uses it to refuse ambiguous product-only
// matches ("http_server" is published by several vendors).
type VendorCounter interface {
	VendorCount(product string) int
}

// maxDescription caps the description kept per CVE: the fact detail needs the
// gist, and the full NVD feed holds hundreds of thousands of descriptions.
const maxDescription = 600

// cveMeta is the per-CVE data shared by all of the CVE's records.
type cveMeta struct {
	id       string
	severity string
	score    float64
	vector   string
	desc     string
	lastMod  string // load-time only: cleared once the index is built
	dead     bool   // superseded by a newer copy, or rejected
}

// Record flags.
const (
	fExact uint8 = 1 << iota
	fStartIncl
	fStartExcl
	fEndIncl
	fEndExcl
)

// rec is one vulnerable cpeMatch in 16 bytes: the full NVD feed holds millions.
// meta indexes the CVE's shared data, the vendor and product are the index keys,
// and lo/hi index the version table: either the exact version (fExact, in lo) or
// the bounds. Version index 0 is "no version".
type rec struct {
	meta   uint32
	lo, hi uint32
	flags  uint8
	plat   PlatformSet // NVD "running on" restriction; 0 = none (fits the padding)
}

// tables are the shared arrays records index into.
type tables struct {
	metas    []cveMeta
	versions []string
}

func (t *tables) entry(r rec, p Product) Entry {
	m := &t.metas[r.meta]
	e := Entry{
		CVE:         m.id,
		Product:     p,
		Severity:    m.severity,
		Score:       m.score,
		Vector:      m.vector,
		Description: m.desc,
		Platforms:   r.plat,
	}
	switch {
	case r.flags&fExact != 0:
		e.ExactVersion = t.versions[r.lo]
	default:
		if r.flags&fStartIncl != 0 {
			e.StartIncluding = t.versions[r.lo]
		}
		if r.flags&fStartExcl != 0 {
			e.StartExcluding = t.versions[r.lo]
		}
		if r.flags&fEndIncl != 0 {
			e.EndIncluding = t.versions[r.hi]
		}
		if r.flags&fEndExcl != 0 {
			e.EndExcluding = t.versions[r.hi]
		}
	}
	return e
}

// LoadStats describes one load of a feed directory.
type LoadStats struct {
	Files      int      `json:"files"`       // feed files read without error
	ErrorFiles int      `json:"error_files"` // feed files that failed to open or decode (partially read data is kept)
	Errors     []string `json:"errors"`      // the first few file errors
	CVEs       int      `json:"cves"`        // live CVEs with at least one vulnerable configuration indexed
	Records    int      `json:"records"`     // vulnerable configuration records indexed
	Products   int      `json:"products"`    // distinct product names indexed
	Rejected   int      `json:"rejected"`    // CVE copies skipped because NVD marks them Rejected
	Superseded int      `json:"superseded"`  // older copies of a CVE replaced by a newer one (by lastModified)
}

// NVDSource is an in-memory index of CVE records keyed by product name, built
// from NVD CVE API 2.0 JSON. It is read-only after construction and safe for
// concurrent Lookup.
//
// Keying by product name lets a product reached through an alias or with an
// out-of-date vendor still find its records; Lookup narrows by vendor when one
// is given.
type NVDSource struct {
	tables
	byProduct map[string]map[string][]rec // product -> vendor -> records
	stats     LoadStats
}

// Lookup returns the entries for p.Product, narrowed to p.Vendor when set (plus
// any vendor-less records). Only the records returned are materialized.
func (s *NVDSource) Lookup(p Product) []Entry {
	if s == nil || p.Product == "" {
		return nil
	}
	vendors := s.byProduct[p.Product]
	var out []Entry
	emit := func(vendor string, recs []rec) {
		pr := Product{Vendor: vendor, Product: p.Product}
		for _, r := range recs {
			out = append(out, s.entry(r, pr))
		}
	}
	if p.Vendor != "" {
		emit(p.Vendor, vendors[p.Vendor])
		emit("", vendors[""])
		return out
	}
	for v, recs := range vendors {
		emit(v, recs)
	}
	return out
}

// Match implements Matcher.
func (s *NVDSource) Match(p Product, version string) []Entry {
	if s == nil || p.Product == "" {
		return nil
	}
	vendors := s.byProduct[p.Product]
	vt := versionTokens(version)
	portable := p.Product == "openssh"
	var out []Entry
	emit := func(vendor string, recs []rec) {
		pr := Product{Vendor: vendor, Product: p.Product}
		for _, r := range recs {
			if s.holds(r, version, vt, portable) {
				out = append(out, s.entry(r, pr))
			}
		}
	}
	if p.Vendor != "" {
		emit(p.Vendor, vendors[p.Vendor])
		emit("", vendors[""])
		return out
	}
	for v, recs := range vendors {
		emit(v, recs)
	}
	return out
}

// holds reports whether the record's constraint admits the version (tokenized as
// vt): a pinned version must be equal, a range must contain it, and an unbounded
// record admits anything. An empty version only satisfies an unbounded record.
func (t *tables) holds(r rec, version string, vt []token, portable bool) bool {
	if r.flags == 0 {
		return true
	}
	if version == "" {
		return false
	}
	lo, hi := t.versions[r.lo], t.versions[r.hi]
	if r.flags&fExact != 0 {
		return compareTokens(vt, versionTokens(lo)) == 0
	}
	if r.flags&fStartIncl != 0 && compareTokens(vt, versionTokens(lo)) < 0 {
		return false
	}
	if r.flags&fStartExcl != 0 && compareTokens(vt, versionTokens(lo)) <= 0 {
		return false
	}
	if r.flags&fEndIncl != 0 && compareTokens(vt, versionTokens(hi)) > 0 && !portableOnBound(version, hi, portable) {
		return false
	}
	if r.flags&fEndExcl != 0 && compareTokens(vt, versionTokens(hi)) >= 0 {
		return false
	}
	return true
}

// VendorCount reports how many distinct vendors publish product.
func (s *NVDSource) VendorCount(product string) int {
	if s == nil {
		return 0
	}
	return len(s.byProduct[product])
}

// Len reports how many product names the index holds.
func (s *NVDSource) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byProduct)
}

// Stats returns the load statistics.
func (s *NVDSource) Stats() LoadStats {
	if s == nil {
		return LoadStats{}
	}
	return s.stats
}

// maxLoadErrors caps the file errors kept in LoadStats.Errors.
const maxLoadErrors = 5

// LoadNVDDir builds an NVDSource from every feed file under dir, recursively.
// Feed files are *.json, *.jsonl and *.ndjson, each optionally gzip-compressed
// (*.gz). Each file may hold, in any mix: NVD CVE API 2.0 responses or the
// official 2.0 JSON feeds ({"vulnerabilities":[{"cve":{...}}]}), feed releases
// listing bare records under "cve_items", bare CVE records ({"id":...,
// "configurations":...}, one per file as in the per-CVE mirror layout, or one per
// line in JSONL), or arrays of these. Dot-files and dot-directories (sync state,
// temporary files, .git) are skipped. When the same CVE appears more than once,
// the copy with the latest lastModified wins; Rejected CVEs are dropped.
//
// A file that fails is counted in ErrorFiles; only an unreadable directory is an
// error.
func LoadNVDDir(dir string) (*NVDSource, error) {
	if st, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("cve feed dir: %w", err)
	} else if !st.IsDir() {
		return nil, fmt.Errorf("cve feed dir: %s is not a directory", dir)
	}
	l := newLoader()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == dir {
				return err
			}
			l.fileError(path, err)
			return nil
		}
		name := d.Name()
		if path != dir && strings.HasPrefix(name, ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !isFeedFile(name) {
			return nil
		}
		if err := l.readFile(path); err != nil {
			l.fileError(path, err)
			return nil
		}
		l.stats.Files++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cve feed dir: %w", err)
	}
	return l.finish(), nil
}

// LoadNVDReader builds an NVDSource from one stream of NVD JSON (any of the
// shapes LoadNVDDir accepts, gzip-compressed or not).
func LoadNVDReader(r io.Reader) (*NVDSource, error) {
	l := newLoader()
	if err := l.readStream(r); err != nil {
		return nil, fmt.Errorf("decode nvd json: %w", err)
	}
	l.stats.Files = 1
	return l.finish(), nil
}

func isFeedFile(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".gz"))
	return strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".jsonl") || strings.HasSuffix(n, ".ndjson")
}

// ---- loader ----

type loader struct {
	tables
	byProduct map[string]map[string][]rec
	byID      map[string]uint32 // CVE id -> index in metas of its latest copy
	intern    map[string]string
	versionID map[string]uint32
	stats     LoadStats
}

func newLoader() *loader {
	return &loader{
		tables:    tables{versions: []string{""}}, // index 0 = no version
		byProduct: map[string]map[string][]rec{},
		byID:      map[string]uint32{},
		intern:    map[string]string{},
		versionID: map[string]uint32{"": 0},
	}
}

func (l *loader) fileError(path string, err error) {
	l.stats.ErrorFiles++
	if len(l.stats.Errors) < maxLoadErrors {
		l.stats.Errors = append(l.stats.Errors, filepath.Base(path)+": "+err.Error())
	}
}

// version returns the version table index of v, adding it when new.
func (l *loader) version(v string) uint32 {
	if id, ok := l.versionID[v]; ok {
		return id
	}
	id := uint32(len(l.versions))
	l.versions = append(l.versions, v)
	l.versionID[v] = id
	return id
}

// str interns s so the many repeated vendor, product, severity and vector strings
// share one copy.
func (l *loader) str(s string) string {
	if s == "" {
		return ""
	}
	if v, ok := l.intern[s]; ok {
		return v
	}
	l.intern[s] = s
	return s
}

func (l *loader) readFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return l.readStream(f)
}

// readStream decodes every top-level JSON value in r (one for .json, many for
// JSONL), transparently gunzipping.
func (l *loader) readStream(r io.Reader) error {
	br := bufio.NewReaderSize(r, 1<<16)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		br = bufio.NewReaderSize(gz, 1<<16)
	}
	dec := json.NewDecoder(br)
	values := 0
	for {
		err := l.readValue(dec)
		if errors.Is(err, io.EOF) {
			if values == 0 {
				return errors.New("no JSON value")
			}
			return nil
		}
		if err != nil {
			return err
		}
		values++
	}
}

// readValue reads one JSON value: an object (response, feed release or bare CVE)
// or an array of such values.
func (l *loader) readValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		return l.readObject(dec)
	case json.Delim('['):
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return unexpectedEOF(err)
			}
			if err := l.readValue(json.NewDecoder(bytes.NewReader(raw))); err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return unexpectedEOF(err)
	}
	return fmt.Errorf("unexpected JSON value %v", tok)
}

// readObject reads the members of an object whose '{' was consumed. Members that
// hold record lists are streamed one record at a time, so a large feed file never
// sits in memory whole; the members of a bare CVE record are collected as they
// come.
func (l *loader) readObject(dec *json.Decoder) error {
	var c nvdCVE
	bare := false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return unexpectedEOF(err)
		}
		key, _ := kt.(string)
		switch key {
		case "vulnerabilities", "cve_items":
			if err := l.readItems(dec); err != nil {
				return err
			}
			continue
		case "cve":
			var cc nvdCVE
			err = dec.Decode(&cc)
			if err == nil {
				l.add(cc)
			}
		case "id":
			bare = true
			err = dec.Decode(&c.ID)
		case "lastModified":
			err = dec.Decode(&c.LastModified)
		case "vulnStatus":
			err = dec.Decode(&c.VulnStatus)
		case "descriptions":
			err = dec.Decode(&c.Descriptions)
		case "metrics":
			err = dec.Decode(&c.Metrics)
		case "configurations":
			err = dec.Decode(&c.Configurations)
		default:
			var skip json.RawMessage
			err = dec.Decode(&skip)
		}
		if err != nil {
			return unexpectedEOF(err)
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return unexpectedEOF(err)
	}
	if bare {
		l.add(c)
	}
	return nil
}

// readItems streams an array of records, each either {"cve":{...}} or a bare
// record.
func (l *loader) readItems(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return unexpectedEOF(err)
	}
	if tok == nil { // "vulnerabilities": null
		return nil
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("record list is not an array")
	}
	for dec.More() {
		var it nvdItem
		if err := dec.Decode(&it); err != nil {
			return unexpectedEOF(err)
		}
		if it.CVE != nil {
			l.add(*it.CVE)
		} else {
			l.add(it.nvdCVE)
		}
	}
	_, err = dec.Token() // ']'
	return unexpectedEOF(err)
}

// unexpectedEOF turns an EOF inside a value into ErrUnexpectedEOF, so that only a
// clean end between top-level values reads as the end of the stream.
func unexpectedEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// add indexes one CVE record, keeping only the latest copy of each CVE.
func (l *loader) add(c nvdCVE) {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		return
	}
	if prev, ok := l.byID[id]; ok {
		pm := &l.metas[prev]
		if pm.lastMod >= c.LastModified {
			return // this copy is not newer than the one indexed
		}
		if !pm.dead {
			pm.dead = true
			l.stats.Superseded++
		}
	}
	if strings.EqualFold(strings.TrimSpace(c.VulnStatus), "rejected") {
		l.stats.Rejected++
		l.byID[id] = uint32(len(l.metas))
		l.metas = append(l.metas, cveMeta{id: id, lastMod: c.LastModified, dead: true})
		return
	}
	sev, score, vector := bestMetric(c.Metrics)
	mi := uint32(len(l.metas))
	l.metas = append(l.metas, cveMeta{
		id:       id,
		severity: l.str(strings.ToUpper(strings.TrimSpace(sev))),
		score:    score,
		vector:   l.str(vector),
		desc:     truncate(englishDescription(c.Descriptions), maxDescription),
		lastMod:  c.LastModified,
	})
	l.byID[id] = mi
	for _, cfg := range c.Configurations {
		plat := configPlatform(cfg)
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				cpe, ok := ParseCPEName(m.Criteria)
				if !ok || cpe.Product == "" || (cpe.Part != "a" && cpe.Part != "o") {
					continue
				}
				r := rec{meta: mi, plat: plat}
				switch {
				case m.VersionStartIncluding != "" || m.VersionStartExcluding != "" ||
					m.VersionEndIncluding != "" || m.VersionEndExcluding != "":
					// A ranged criteria can still name an update: OpenSSH's
					// "openssh:*:p2 <= 7.2" (CVE-2016-6210) means up to 7.2p2. The
					// update belongs to the upper bound (or the lower one alone).
					start, end := m.VersionStartIncluding, m.VersionEndIncluding
					if start == "" {
						start = m.VersionStartExcluding
					}
					if end == "" {
						end = m.VersionEndExcluding
					}
					if cpe.Update != "" {
						if end != "" {
							end += cpe.Update
						} else {
							start += cpe.Update
						}
					}
					if m.VersionStartIncluding != "" {
						r.flags |= fStartIncl
						r.lo = l.version(start)
					} else if m.VersionStartExcluding != "" {
						r.flags |= fStartExcl
						r.lo = l.version(start)
					}
					if m.VersionEndIncluding != "" {
						r.flags |= fEndIncl
						r.hi = l.version(end)
					} else if m.VersionEndExcluding != "" {
						r.flags |= fEndExcl
						r.hi = l.version(end)
					}
				case cpe.FullVersion() != "":
					r.flags = fExact
					r.lo = l.version(cpe.FullVersion())
				}
				applyErrata(id, cpe, &r, l.versions)
				product, vendor := l.str(cpe.Product), l.str(cpe.Vendor)
				vendors := l.byProduct[product]
				if vendors == nil {
					vendors = map[string][]rec{}
					l.byProduct[product] = vendors
				}
				vendors[vendor] = append(vendors[vendor], r)
			}
		}
	}
}

// configPlatform returns the platforms an AND configuration limits its vulnerable
// records to: the families of the CPEs in its nodes that hold no vulnerable match
// (NVD's "running on" nodes, such as o:microsoft:windows for CVE-2024-4577). A
// plain configuration, or one that negates, restricts nothing.
func configPlatform(cfg nvdConfigNode) PlatformSet {
	if !strings.EqualFold(cfg.Operator, "AND") || cfg.Negate {
		return 0
	}
	var plat PlatformSet
	for _, n := range cfg.Nodes {
		vulnerable := false
		for _, m := range n.CPEMatch {
			vulnerable = vulnerable || m.Vulnerable
		}
		if vulnerable {
			continue
		}
		if n.Negate {
			return 0 // "not running on X" is not a platform restriction we can use
		}
		for _, m := range n.CPEMatch {
			if c, ok := ParseCPEName(m.Criteria); ok {
				plat |= platformOf(c)
			} else {
				plat |= PlatformOther
			}
		}
	}
	return plat
}

// erratum corrects one NVD record bound that is demonstrably wrong.
type erratum struct {
	cve, product string
	endIncluding string // an inclusive upper bound that should be exclusive
}

// errata lists known NVD mistakes that would otherwise flag a fixed release:
//   - CVE-2024-6387 (regreSSHion) is filed as openssh "<= 9.8", but 9.8/9.8p1 is
//     the fix release (OpenSSH 9.8 release notes); the bound is exclusive.
var errata = []erratum{{cve: "CVE-2024-6387", product: "openssh", endIncluding: "9.8"}}

func applyErrata(id string, cpe CPE, r *rec, versions []string) {
	for _, e := range errata {
		if e.cve == id && e.product == cpe.Product && r.flags&fEndIncl != 0 && versions[r.hi] == e.endIncluding {
			r.flags = r.flags&^fEndIncl | fEndExcl
		}
	}
}

// portableOnBound reports whether an OpenSSH portable release sits on an
// inclusive upper bound that names the bare release: NVD writes "<= 7.9" for
// "through release 7.9", which includes the portable 7.9p1 every Linux sshd
// reports (CVE-2019-6111, CVE-2018-15473 "<= 7.7", CVE-2016-20012 "<= 8.7").
func portableOnBound(version, bound string, portable bool) bool {
	if !portable || portableSuffixRe.MatchString(bound) {
		return false
	}
	base := stripPortable(version)
	return base != version && CompareVersions(base, bound) == 0
}

// finish drops superseded/rejected records, trims every bucket to its size and
// releases the load-time maps.
func (l *loader) finish() *NVDSource {
	live := make([]bool, len(l.metas))
	for product, vendors := range l.byProduct {
		for vendor, recs := range vendors {
			kept := make([]rec, 0, len(recs))
			for _, r := range recs {
				if !l.metas[r.meta].dead {
					kept = append(kept, r)
					live[r.meta] = true
				}
			}
			if len(kept) == 0 {
				delete(vendors, vendor)
				continue
			}
			vendors[vendor] = kept // an exact-size copy: dropped records are not kept alive
			l.stats.Records += len(kept)
		}
		if len(vendors) == 0 {
			delete(l.byProduct, product)
		}
	}
	for i := range l.metas {
		l.metas[i].lastMod = "" // only needed to pick the latest copy while loading
		if live[i] {
			l.stats.CVEs++
		} else {
			l.metas[i].desc, l.metas[i].vector = "", "" // unreferenced: let the text go
		}
	}
	l.stats.Products = len(l.byProduct)
	src := &NVDSource{
		tables:    tables{metas: slicesClip(l.metas), versions: slicesClip(l.versions)},
		byProduct: l.byProduct,
		stats:     l.stats,
	}
	l.byProduct, l.byID, l.intern, l.versionID, l.tables = nil, nil, nil, nil, tables{}
	return src
}

// slicesClip returns s with its spare capacity released.
func slicesClip[T any](s []T) []T { return append([]T(nil), s...) }

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// ---- NVD 2.0 JSON shapes (only the fields we read) ----

type nvdItem struct {
	nvdCVE
	CVE *nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string           `json:"id"`
	LastModified   string           `json:"lastModified"`
	VulnStatus     string           `json:"vulnStatus"`
	Descriptions   []nvdDescription `json:"descriptions"`
	Metrics        nvdMetrics       `json:"metrics"`
	Configurations []nvdConfigNode  `json:"configurations"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
	V2  []nvdMetric `json:"cvssMetricV2"`
}

type nvdMetric struct {
	Type     string `json:"type"` // Primary | Secondary
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	// CVSS v2 carries severity as a sibling of cvssData.
	BaseSeverity string `json:"baseSeverity"`
}

type nvdConfigNode struct {
	Operator string    `json:"operator"` // "AND": the vulnerable nodes hold only on the platform nodes
	Negate   bool      `json:"negate"`
	Nodes    []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// bestMetric picks the preferred CVSS metric: v3.1, then v3.0, then v4.0, then
// v2; within a version the NVD "Primary" score wins over a CNA's "Secondary".
func bestMetric(m nvdMetrics) (severity string, score float64, vector string) {
	for _, group := range [][]nvdMetric{m.V31, m.V30, m.V40} {
		if d, ok := primary(group); ok {
			return d.CVSSData.BaseSeverity, d.CVSSData.BaseScore, d.CVSSData.VectorString
		}
	}
	if d, ok := primary(m.V2); ok {
		return d.BaseSeverity, d.CVSSData.BaseScore, d.CVSSData.VectorString
	}
	return "", 0, ""
}

func primary(group []nvdMetric) (nvdMetric, bool) {
	if len(group) == 0 {
		return nvdMetric{}, false
	}
	for _, d := range group {
		if strings.EqualFold(d.Type, "primary") {
			return d, true
		}
	}
	return group[0], true
}

func englishDescription(ds []nvdDescription) string {
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

// Lookup implements Source with the same vendor narrowing as NVDSource.
func (m MapSource) Lookup(p Product) []Entry {
	if p.Product == "" {
		return nil
	}
	var out []Entry
	for _, e := range m[p.Product] {
		if p.Vendor != "" && e.Product.Vendor != "" && e.Product.Vendor != p.Vendor {
			continue
		}
		out = append(out, e)
	}
	return out
}

// VendorCount implements VendorCounter.
func (m MapSource) VendorCount(product string) int {
	seen := map[string]struct{}{}
	for _, e := range m[product] {
		seen[e.Product.Vendor] = struct{}{}
	}
	return len(seen)
}
