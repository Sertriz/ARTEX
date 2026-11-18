package cvematch

import (
	"sort"
	"strings"
)

// Observation is one service as ARTEX knows it. Any field may be empty.
type Observation struct {
	// CPEs are the service's CPEs (nmap -sV). Application CPEs are correlated;
	// operating-system CPEs only serve as a distribution hint, since they describe
	// nmap's guess of the host OS, not the service.
	CPEs []string
	// Product is a free product name: an nmap product string ("Apache httpd"), an
	// httpx/wappalyzer technology ("Nginx") or a Server-header token ("Microsoft-IIS").
	Product string
	// Version is the observed version string, raw ("8.2p1 Ubuntu 4ubuntu0.5").
	Version string
	// Extra is text that may reveal the distribution build: nmap extrainfo/ostype,
	// or the comment of a Server header ("(Ubuntu)").
	Extra string
}

// Candidate is one CVE the observed service may be affected by. It is an
// UNVERIFIED lead: a version/product match, not a confirmed weakness.
type Candidate struct {
	CVE         string
	Product     Product // the vendor:product whose record matched
	Severity    string  // CRITICAL|HIGH|MEDIUM|LOW|NONE|""
	Score       float64 // CVSS base score; 0 when unknown
	Vector      string
	Description string // inert third-party text; never interpreted
	// MatchBasis records why this CVE matched, for the fact detail:
	// "8.2p1 in [6.2,8.8)", "8.5p1 == 8.5p1", or "no version bounds".
	MatchBasis string
	// VersionConfirmed is true when the observed version was placed inside a
	// range or equals a pinned version.
	VersionConfirmed bool
	// Unbounded is true when the record names no version at all, so it matched on
	// the product alone: a weak lead, often stale NVD data.
	Unbounded bool
	// BackportRisk is true for a version-confirmed match on a distribution build,
	// whose package may carry the fix without a new upstream version.
	BackportRisk bool
}

// Result is the outcome of correlating one observation.
type Result struct {
	Candidates []Candidate // version-confirmed first, then by score
	Products   []Product   // the canonical products looked up
	Version    string      // the normalized version matched ("" when none)
	Distro     string      // detected distribution ("" when none)
}

// Confirmed returns the version-confirmed candidates.
func (r Result) Confirmed() []Candidate {
	var out []Candidate
	for _, c := range r.Candidates {
		if c.VersionConfirmed {
			out = append(out, c)
		}
	}
	return out
}

// Correlate returns the candidate CVEs for one observation (see CorrelateResult).
func Correlate(obs Observation, src Source) []Candidate {
	return CorrelateResult(obs, src).Candidates
}

// CorrelateResult resolves the observation to canonical products, normalizes its
// version and matches every record of those products. It performs no I/O; src
// supplies the CVE knowledge.
//
// Matching is conservative: a record with a pinned version or a version range is
// only kept when the observed version is known and inside it. A record with no
// version at all is kept as Unbounded. Candidates are deduplicated by CVE (a
// version-confirmed match beats an unbounded one) and ranked version-confirmed
// first, then by CVSS score.
func CorrelateResult(obs Observation, src Source) Result {
	if src == nil {
		return Result{}
	}
	products, cpeVersion, distro := resolve(obs, src)
	version := NormalizeVersion(cpeVersion)
	if version == "" {
		version = NormalizeVersion(obs.Version)
	}
	if distro == "" {
		distro = DetectDistro(obs.Version, obs.Extra)
	}
	for _, p := range products {
		if p.Product == "mariadb" && strings.HasPrefix(version, mariadbCompatPrefix) {
			version = NormalizeVersion(strings.TrimSuffix(strings.TrimPrefix(version, mariadbCompatPrefix), "-mariadb"))
			break
		}
	}
	res := Result{Products: products, Version: version, Distro: distro}

	best := map[string]Candidate{}
	for _, p := range products {
		for _, e := range lookup(src, p, version) {
			cand, ok := matchEntry(e, version)
			if !ok {
				continue
			}
			cand.BackportRisk = cand.VersionConfirmed && distro != ""
			if cur, exists := best[cand.CVE]; !exists || better(cand, cur) {
				best[cand.CVE] = cand
			}
		}
	}
	for _, c := range best {
		res.Candidates = append(res.Candidates, c)
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		a, b := res.Candidates[i], res.Candidates[j]
		if a.VersionConfirmed != b.VersionConfirmed {
			return a.VersionConfirmed
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.CVE > b.CVE
	})
	return res
}

// resolve maps the observation to the canonical products to look up, the version
// carried by an application CPE, and a distribution named by an OS CPE.
func resolve(obs Observation, src Source) (products []Product, cpeVersion, distro string) {
	seen := map[string]bool{}
	add := func(ps ...Product) {
		for _, p := range ps {
			if p.Product == "" || seen[p.key()] {
				continue
			}
			seen[p.key()] = true
			products = append(products, p)
		}
	}
	for _, s := range obs.CPEs {
		c, ok := ParseCPEName(s)
		if !ok {
			continue
		}
		switch c.Part {
		case "a":
			add(Canonical(c.Prod())...)
			if cpeVersion == "" {
				cpeVersion = c.FullVersion()
			}
		case "o":
			if d := distroFromOSCPE(c); d != "" && distro == "" {
				distro = d
			}
		}
	}
	if obs.Product != "" {
		if ps := AliasProducts(obs.Product); len(ps) > 0 {
			add(ps...)
		} else if len(products) == 0 {
			// An unknown name is only trusted when NVD publishes that product name
			// under exactly one vendor; otherwise it is ambiguous and skipped.
			if p := NormalizeProductName(obs.Product); vendorCount(src, p.Product) == 1 {
				add(p)
			}
		}
	}
	return products, cpeVersion, distro
}

// lookup returns the records for p that may hold version (all of p's records
// when the source cannot filter). When p names a vendor the source does not use
// for that product (a renamed vendor missing from the alias table) and the product
// name is published by exactly one vendor, that vendor's records are used.
func lookup(src Source, p Product, version string) []Entry {
	get := src.Lookup
	if m, ok := src.(Matcher); ok {
		get = func(p Product) []Entry { return m.Match(p, version) }
	}
	if p.Vendor != "" && vendorCount(src, p.Product) == 1 && !hasVendor(src, p) {
		return get(Product{Product: p.Product})
	}
	return get(p)
}

// hasVendor reports whether the source files p's product under p's vendor.
func hasVendor(src Source, p Product) bool {
	if s, ok := src.(*NVDSource); ok {
		_, found := s.byProduct[p.Product][p.Vendor]
		return found
	}
	return len(src.Lookup(p)) > 0
}

func vendorCount(src Source, product string) int {
	if product == "" {
		return 0
	}
	if vc, ok := src.(VendorCounter); ok {
		return vc.VendorCount(product)
	}
	return 0
}

// matchEntry decides whether an Entry applies to the observed version.
func matchEntry(e Entry, version string) (Candidate, bool) {
	cand := Candidate{
		CVE:         e.CVE,
		Product:     e.Product,
		Severity:    e.Severity,
		Score:       e.Score,
		Vector:      e.Vector,
		Description: e.Description,
	}
	// Plain ordering is right for NVD's conventions: OpenSSH 9.8 < 9.8p1, so the
	// fix release 9.8p1 falls outside "<= 9.8", and 9.3p2 does not equal the
	// pinned 9.3 (update "-") or 9.3p1.
	switch {
	case e.ExactVersion != "":
		if version == "" || CompareVersions(version, e.ExactVersion) != 0 {
			return Candidate{}, false
		}
		cand.MatchBasis = version + " == " + e.ExactVersion
		cand.VersionConfirmed = true
	case e.hasRange():
		if version == "" || !versionInRange(version, e) {
			return Candidate{}, false
		}
		cand.MatchBasis = version + " in " + rangeString(e)
		cand.VersionConfirmed = true
	default:
		cand.MatchBasis = "no version bounds"
		cand.Unbounded = true
	}
	return cand, true
}

// versionInRange reports whether version satisfies the entry's bounds. An absent
// bound does not constrain that side.
func versionInRange(version string, e Entry) bool {
	if e.StartIncluding != "" && CompareVersions(version, e.StartIncluding) < 0 {
		return false
	}
	if e.StartExcluding != "" && CompareVersions(version, e.StartExcluding) <= 0 {
		return false
	}
	if e.EndIncluding != "" && CompareVersions(version, e.EndIncluding) > 0 {
		return false
	}
	if e.EndExcluding != "" && CompareVersions(version, e.EndExcluding) >= 0 {
		return false
	}
	return true
}

// rangeString renders an entry's bounds as an interval, e.g. "[8.0,8.5)".
func rangeString(e Entry) string {
	lo, hi := "(-inf", "+inf)"
	switch {
	case e.StartIncluding != "":
		lo = "[" + e.StartIncluding
	case e.StartExcluding != "":
		lo = "(" + e.StartExcluding
	}
	switch {
	case e.EndIncluding != "":
		hi = e.EndIncluding + "]"
	case e.EndExcluding != "":
		hi = e.EndExcluding + ")"
	}
	return lo + "," + hi
}

// better ranks one matched candidate above another for the dedup map: a
// version-confirmed match beats an unbounded one, then the higher score wins.
func better(a, b Candidate) bool {
	if a.VersionConfirmed != b.VersionConfirmed {
		return a.VersionConfirmed
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.Product.String() < b.Product.String() // deterministic whatever the lookup order
}
