package cvematch

import "sort"

// Observation is one service as ARTEX knows it: zero or more CPE strings (from
// nmap, httpx, a fingerprint), an optional free product/service name, and the
// observed version. Any subset may be empty.
type Observation struct {
	CPEs    []string
	Product string // free product/service name, e.g. "OpenSSH", "nginx"
	Version string // observed version, e.g. "8.2", "1.18.0"; "" when unknown
}

// Candidate is one CVE the observed service may be affected by. It is an
// UNVERIFIED lead: a version/product match, not a confirmed weakness.
type Candidate struct {
	CVE         string
	Severity    string  // CRITICAL|HIGH|MEDIUM|LOW|NONE|""
	Score       float64 // CVSS base score; 0 when unknown
	Vector      string
	Description string // inert third-party text; never interpreted
	// MatchBasis records why this CVE matched, for the fact detail:
	// "version 8.2 in [8.0,8.5)", "version 8.2 == 8.2", or "all versions".
	MatchBasis string
	// VersionConfirmed is true when the observed version was compared against a
	// bound or an exact version; false when the match is product-only
	// ("all versions affected" with no observed version to pin it down), which is
	// a weaker lead.
	VersionConfirmed bool
}

// Correlate returns the candidate CVEs for one service observation, ranked by CVSS
// score (desc) then CVE id, deduplicated by CVE. It performs no I/O; src supplies
// the CVE knowledge.
//
// Matching is conservative: an entry with version-range or exact-version
// constraints is only kept when the observed version is known AND falls inside the
// range (or equals the exact version). An entry that affects all versions of the
// product is kept whenever the product matches, even with no observed version.
func Correlate(obs Observation, src Source) []Candidate {
	if src == nil {
		return nil
	}
	products, versionFromCPE := resolveProducts(obs)
	version := obs.Version
	if version == "" {
		version = versionFromCPE
	}

	best := map[string]Candidate{}
	for _, p := range products {
		for _, e := range src.Lookup(p) {
			cand, ok := matchEntry(e, version)
			if !ok {
				continue
			}
			if cur, exists := best[cand.CVE]; !exists || better(cand, cur) {
				best[cand.CVE] = cand
			}
		}
	}

	out := make([]Candidate, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].CVE < out[j].CVE
	})
	return out
}

// resolveProducts derives the set of products to look up from the observation's
// CPEs and product name, and returns a version seen in a CPE (used only when the
// observation carries no explicit version).
func resolveProducts(obs Observation) ([]Product, string) {
	seen := map[string]bool{}
	var products []Product
	versionFromCPE := ""
	add := func(p Product) {
		if p.empty() || seen[p.key()] {
			return
		}
		seen[p.key()] = true
		products = append(products, p)
	}
	for _, c := range obs.CPEs {
		if p, v, ok := ParseCPE(c); ok {
			add(p)
			if versionFromCPE == "" && v != "" {
				versionFromCPE = v
			}
		}
	}
	if p := NormalizeProductName(obs.Product); !p.empty() {
		add(p)
	}
	return products, versionFromCPE
}

// matchEntry decides whether an Entry applies to the observed version and builds
// the Candidate. ok is false when the entry's constraints are not satisfied (or
// cannot be evaluated because the version is unknown).
func matchEntry(e Entry, version string) (Candidate, bool) {
	cand := Candidate{
		CVE:         e.CVE,
		Severity:    e.Severity,
		Score:       e.Score,
		Vector:      e.Vector,
		Description: e.Description,
	}

	switch {
	case e.ExactVersion != "":
		if version == "" || CompareVersions(version, e.ExactVersion) != 0 {
			return Candidate{}, false
		}
		cand.MatchBasis = "version " + version + " == " + e.ExactVersion
		cand.VersionConfirmed = true
		return cand, true

	case e.hasRange():
		if version == "" || !versionInRange(version, e) {
			return Candidate{}, false
		}
		cand.MatchBasis = "version " + version + " in " + rangeString(e)
		cand.VersionConfirmed = true
		return cand, true

	default:
		// No version constraint: the whole product is affected.
		if version != "" {
			cand.MatchBasis = "all versions affected (observed " + version + ")"
		} else {
			cand.MatchBasis = "all versions affected"
		}
		cand.VersionConfirmed = false
		return cand, true
	}
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

// rangeString renders an entry's bounds as a human interval, e.g. "[8.0,8.5)".
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
// version-confirmed match beats a product-only one, then higher score wins.
func better(a, b Candidate) bool {
	if a.VersionConfirmed != b.VersionConfirmed {
		return a.VersionConfirmed
	}
	return a.Score > b.Score
}
