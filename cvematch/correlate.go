package cvematch

import (
	"sort"
	"strconv"
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
	Version     string  // the observed (normalized) version the record was matched with
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
	// Platforms is set when NVD limits the CVE to platforms the observation could
	// not confirm (the lead holds only if the host runs one of them): the host's
	// platform is unknown, its Linux distribution is unknown and the record names
	// distributions, or the record also names a platform outside the known
	// families ("other") that the scan cannot rule out. A record whose platforms
	// the observation contradicts is not a candidate at all.
	Platforms PlatformSet
}

// Result is the outcome of correlating one observation.
type Result struct {
	// Candidates are version-confirmed first, then not platform-conditional, then
	// by score.
	Candidates []Candidate
	Products   []Product   // the canonical products looked up
	Version    string      // the primary product's normalized version ("" when none)
	Distro     string      // detected distribution ("" when none)
	Platform   PlatformSet // the OS family the observation revealed (0 when none)
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

// Key identifies what an observation correlates as: observations with the same
// key yield the same Result, whatever else their banners say. It reads no record,
// so it is cheap next to CorrelateResult and suits memoizing a scan's services.
func Key(obs Observation, src Source) string {
	targets, osCPEs := resolve(obs, src)
	distro := observedDistro(obs, osCPEs)
	var b strings.Builder
	for _, t := range targets {
		b.WriteString(t.p.String())
		b.WriteByte('@')
		b.WriteString(t.version)
		b.WriteByte(',')
	}
	b.WriteString("|" + distro + "|")
	b.WriteString(strconv.Itoa(int(observedPlatform(osCPEs, distro, obs.Extra, obs.Version))))
	return b.String()
}

// observedDistro is the distribution an OS CPE names, else the one the banner
// text names.
func observedDistro(obs Observation, osCPEs []CPE) string {
	for _, c := range osCPEs {
		if d := distroFromOSCPE(c); d != "" {
			return d
		}
	}
	return DetectDistro(obs.Version, obs.Extra)
}

// target is one product to look up, with the version observed for it.
type target struct {
	p       Product
	version string
}

// CorrelateResult resolves the observation to canonical products, each with its
// own observed version, and matches every record of those products. It performs
// no I/O; src supplies the CVE knowledge.
//
// Matching is conservative: a record with a pinned version or a version range is
// only kept when the product's version is known and inside it; a record NVD
// limits to a platform the observation contradicts is dropped. A record with no
// version at all is kept as Unbounded. Candidates are deduplicated by CVE (a
// version-confirmed match beats an unbounded one).
func CorrelateResult(obs Observation, src Source) Result {
	if src == nil {
		return Result{}
	}
	targets, osCPEs := resolve(obs, src)
	distro := observedDistro(obs, osCPEs)
	res := Result{Distro: distro, Platform: observedPlatform(osCPEs, distro, obs.Extra, obs.Version)}
	for i, t := range targets {
		res.Products = append(res.Products, t.p)
		if i == 0 {
			res.Version = t.version
		}
	}

	best := map[string]Candidate{}
	for _, t := range targets {
		for _, e := range lookup(src, t.p, t.version) {
			if contradicts(e.Platforms, res.Platform, distro) {
				continue
			}
			cand, ok := matchEntry(e, t.version)
			if !ok {
				continue
			}
			cand.BackportRisk = cand.VersionConfirmed && distro != ""
			if conditional(e.Platforms, res.Platform, distro) {
				cand.Platforms = e.Platforms
			}
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
		if (a.Platforms == 0) != (b.Platforms == 0) {
			return a.Platforms == 0
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.CVE > b.CVE
	})
	return res
}

// resolve maps the observation to the products to look up, each with the version
// observed for it, and returns the OS CPEs (a distribution and platform hint).
//
// Each application CPE keeps its own version: nmap emits several for one service
// (BaseHTTPServer's version, then Python's), and one product must never be
// checked against another's version. A CPE version is trusted only when it is
// what the banner says: when nmap could read just a series, a bound or a range
// ("4.X", "3.11 or later", "5.12.0 - 5.15.4"), its CPE carries the truncated
// series ("4", "3", "5"), which is not a version either; when the CPE truncates a
// full banner version ("13" vs "13.23"), the banner's is used.
func resolve(obs Observation, src Source) (targets []target, osCPEs []CPE) {
	raw := strings.ToLower(strings.TrimSpace(obs.Version))
	obsVersion := NormalizeVersion(raw)
	notAVersion := raw != "" && obsVersion == ""

	var appCPEs []CPE
	for _, s := range obs.CPEs {
		c, ok := ParseCPEName(s)
		if !ok {
			continue
		}
		switch c.Part {
		case "a":
			appCPEs = append(appCPEs, c)
		case "o":
			osCPEs = append(osCPEs, c)
		}
	}
	seen := map[string]bool{}
	add := func(version string, ps ...Product) {
		for _, p := range ps {
			if p.Product == "" || seen[p.key()] {
				continue
			}
			seen[p.key()] = true
			targets = append(targets, target{p: p, version: productVersion(p, version)})
		}
	}
	for _, c := range appCPEs {
		v := NormalizeVersion(c.FullVersion())
		switch {
		case v != "" && notAVersion && strings.HasPrefix(raw, v):
			v = "" // the CPE holds the series of a banner that is not a version
		case v != "" && obsVersion != "" && strings.HasPrefix(obsVersion, v+"."):
			v = obsVersion // the CPE truncated the banner's version
		case v == "" && len(appCPEs) == 1:
			v = obsVersion // one product: the banner's version is its version
		}
		add(v, Canonical(c.Prod())...)
	}
	if obs.Product != "" {
		if ps := AliasProducts(obs.Product); len(ps) > 0 {
			add(obsVersion, ps...)
		} else if len(appCPEs) == 0 {
			// An unknown name is only trusted when NVD publishes that product name
			// under exactly one vendor; otherwise it is ambiguous and skipped.
			if p := NormalizeProductName(obs.Product); vendorCount(src, p.Product) == 1 {
				add(obsVersion, p)
			}
		}
	}
	return targets, osCPEs
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
//
// Plain token order follows NVD's conventions (OpenSSH 9.3p1 < 9.3p2, OpenSSL
// 1.0.1f < 1.0.1g), with one OpenSSH rule: an inclusive upper bound or a pin with
// update ANY that names a bare release ("<= 7.9", "8.2:*") includes that
// release's portable builds (7.9p1, 8.2p1), see portableOnBound. Otherwise a
// pinned version must match exactly: NVD pins 9.3 (update "-") and 9.3p1
// separately. A record limited to an edition needs the version to show it.
func matchEntry(e Entry, version string) (Candidate, bool) {
	cand := Candidate{
		CVE:         e.CVE,
		Product:     e.Product,
		Version:     version,
		Severity:    e.Severity,
		Score:       e.Score,
		Vector:      e.Vector,
		Description: e.Description,
	}
	if e.Edition != "" && !editionShown(e.Product.Product, version) {
		return Candidate{}, false
	}
	portable := e.Product.Product == "openssh"
	switch {
	case e.ExactVersion != "":
		switch {
		case version == "":
			return Candidate{}, false
		case CompareVersions(version, e.ExactVersion) == 0:
			cand.MatchBasis = version + " == " + e.ExactVersion
		case e.AnyUpdate && portableOnBound(version, e.ExactVersion, portable):
			cand.MatchBasis = version + " is a portable build of " + e.ExactVersion
		default:
			return Candidate{}, false
		}
		cand.VersionConfirmed = true
	case e.hasRange():
		inRange := version != ""
		if inRange && e.Edition != "" {
			b := e
			b.StartIncluding, b.StartExcluding = editionBase(e.Product.Product, e.StartIncluding), editionBase(e.Product.Product, e.StartExcluding)
			b.EndIncluding, b.EndExcluding = editionBase(e.Product.Product, e.EndIncluding), editionBase(e.Product.Product, e.EndExcluding)
			inRange = versionInRange(editionBase(e.Product.Product, version), b, portable)
		} else if inRange {
			inRange = versionInRange(version, e, portable)
		}
		if !inRange {
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
func versionInRange(version string, e Entry, portable bool) bool {
	if e.StartIncluding != "" && CompareVersions(version, e.StartIncluding) < 0 {
		return false
	}
	if e.StartExcluding != "" && CompareVersions(version, e.StartExcluding) <= 0 {
		return false
	}
	if e.EndIncluding != "" && CompareVersions(version, e.EndIncluding) > 0 && !portableOnBound(version, e.EndIncluding, portable) {
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
	// An unconditional record of the CVE beats one limited to a platform the
	// observation did not show (CVE-2007-5795 has both for Emacs <= 22.1).
	if (a.Platforms == 0) != (b.Platforms == 0) {
		return a.Platforms == 0
	}
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.Product.String() < b.Product.String() // deterministic whatever the lookup order
}
