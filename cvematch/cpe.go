// Package cvematch is an engine-side, non-AI, deterministic layer that turns a
// service's known product/version (or CPE) into candidate CVEs for the planner.
// It is a planning aid, not an exploit engine: it performs no network I/O, acts on
// nothing, and every CVE it emits is an UNVERIFIED lead that a worker must confirm.
//
// The matching is intentionally conservative about what counts as "the same
// product" (canonical vendor:product pairs, see aliases.go) and about version
// ranges, because a version match is a lead — banners lie, distributions backport
// fixes without bumping the version, and a CPE can be wrong.
package cvematch

import (
	"regexp"
	"strconv"
	"strings"
)

// Product identifies a piece of software by its CPE vendor and product fields,
// both lowercased. A zero Product (empty vendor and product) matches nothing.
type Product struct {
	Vendor  string
	Product string
}

func (p Product) empty() bool { return p.Vendor == "" && p.Product == "" }

// key is "vendor:product" (":product" with no vendor), used for dedup.
func (p Product) key() string { return p.Vendor + ":" + p.Product }

// String is "vendor:product", or just the product when no vendor is known.
func (p Product) String() string {
	if p.Vendor == "" {
		return p.Product
	}
	return p.Vendor + ":" + p.Product
}

// CPE is a parsed CPE name. Every field is lowercased and unescaped, and the
// wildcards "*" (any) and "-" (not applicable) are mapped to "".
type CPE struct {
	Part    string // "a" application, "o" operating system, "h" hardware
	Vendor  string
	Product string
	Version string
	Update  string
	// UpdateAny is true when the update field is the wildcard ANY ("*", or absent),
	// which covers every update of the version; NA ("-") says there is none. Both
	// leave Update empty, and NVD uses the difference: "openssh:8.2:*" covers the
	// portable 8.2p1, "openssh:9.3:-" does not.
	UpdateAny bool
	// SWEdition is the CPE 2.3 software edition ("supported_preview" for ISC's
	// BIND -S builds), "" for ANY or NA.
	SWEdition string
}

// Prod returns the vendor:product identity.
func (c CPE) Prod() Product { return Product{Vendor: c.Vendor, Product: c.Product} }

// FullVersion joins version and update the way banners print them. NVD records
// OpenSSH 8.5p1 as version "8.5" with update "p1", while nmap reports "8.5p1".
// With no version there is no full version, whatever the update says.
func (c CPE) FullVersion() string {
	if c.Version == "" {
		return ""
	}
	return c.Version + c.Update
}

// ParseCPEName parses a CPE 2.2 URI ("cpe:/a:openbsd:openssh:8.2p1") or a CPE 2.3
// formatted string ("cpe:2.3:a:openbsd:openssh:8.5:p1:*:..."). ok is false when s
// is not a CPE or names neither a vendor nor a product.
func ParseCPEName(s string) (CPE, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	var f []string
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		f = splitCPE23(s[len("cpe:2.3:"):])
	case strings.HasPrefix(s, "cpe:/"):
		f = strings.Split(s[len("cpe:/"):], ":")
	default:
		return CPE{}, false
	}
	if len(f) < 3 {
		return CPE{}, false
	}
	c := CPE{Part: cpeField(f[0]), Vendor: cpeField(f[1]), Product: cpeField(f[2])}
	if len(f) >= 4 {
		c.Version = cpeField(f[3])
	}
	c.UpdateAny = true
	if len(f) >= 5 {
		c.Update = cpeField(f[4])
		c.UpdateAny = f[4] == "*" || f[4] == ""
	}
	if strings.HasPrefix(s, "cpe:2.3:") && len(f) >= 8 {
		c.SWEdition = cpeField(f[7])
	}
	if c.Vendor == "" && c.Product == "" {
		return CPE{}, false
	}
	return c, true
}

// ParseCPE parses a CPE and returns its vendor/product and full version. Only the
// application ("a") and operating-system ("o") parts are accepted.
func ParseCPE(s string) (prod Product, version string, ok bool) {
	c, ok := ParseCPEName(s)
	if !ok || (c.Part != "a" && c.Part != "o") {
		return Product{}, "", false
	}
	return c.Prod(), c.FullVersion(), true
}

// splitCPE23 splits on unescaped colons. CPE 2.3 escapes a literal colon as "\:".
func splitCPE23(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == ':' {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(s[i])
	}
	return append(out, cur.String())
}

// cpeField unescapes a CPE 2.3 field and maps the wildcards "*" and "-" to "".
func cpeField(s string) string {
	if s == "*" || s == "-" || s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "\\", "")
}

// NormalizeProductName maps a free product/service name (an nmap product string,
// a service_name, a technology label) to a best-effort Product with an empty
// vendor. It lowercases, keeps letters, digits, '-', '_' and '.', and joins words
// with '_' the way NVD product names are written. It returns an empty Product when
// nothing usable remains.
func NormalizeProductName(name string) Product {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	prevSpace := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
			prevSpace = false
		case r == ' ' || r == '\t':
			if !prevSpace && b.Len() > 0 {
				b.WriteByte('_')
			}
			prevSpace = true
		default:
			prevSpace = false
		}
	}
	p := strings.Trim(b.String(), "_")
	if p == "" {
		return Product{}
	}
	return Product{Product: p}
}

// versionDigitRe requires at least one digit in a version.
var versionDigitRe = regexp.MustCompile(`[0-9]`)

// NormalizeVersion reduces an observed version string to the comparable version
// token: the text up to the first space, '(' , ',' or ';' (nmap prints
// "8.2p1 Ubuntu 4ubuntu0.5", servers print "2.4.41 (Ubuntu)"), lowercased, with a
// leading "v" before a digit dropped. It returns "" when no digit remains, since a
// version that cannot be ordered must not place anything inside a range.
func NormalizeVersion(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	// nmap prints a bound, a range or alternatives when it cannot pin the version
	// ("10.3.23 or earlier", "1.6.0 - 1.9.0", "9.6.20 - 9.6.23 or 11.14 - 11.18"):
	// none is a version, and placing its first number inside a range would claim a
	// match nmap never saw.
	if strings.Contains(v, " or ") || versionRangeRe.MatchString(v) {
		return ""
	}
	if i := strings.IndexAny(v, " \t(,;"); i >= 0 {
		v = v[:i]
	}
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	v = strings.Trim(v, ".-_+~")
	if len(v) > 64 || !versionDigitRe.MatchString(v) || versionWildcardRe.MatchString(v) {
		return ""
	}
	return v
}

// versionWildcardRe matches a version with a wildcard component ("2.4.x", "5.*"),
// which names a series, not a version.
var versionWildcardRe = regexp.MustCompile(`(^|[.\-])(x|\*)($|[.\-])`)

// versionRangeRe matches nmap's "A - B" version ranges.
var versionRangeRe = regexp.MustCompile(`[0-9a-z]\S*\s+-\s+[0-9]`)

// portableSuffixRe matches an OpenSSH portable release suffix ("9.6p1").
var portableSuffixRe = regexp.MustCompile(`^(.*[0-9])p[0-9]+$`)

// stripPortable returns an OpenSSH portable version without its "p<n>" suffix
// ("7.9p1" -> "7.9"), or v unchanged.
func stripPortable(v string) string {
	if m := portableSuffixRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return v
}

// mysqlUpstreamRe is the upstream X.Y.Z of a MySQL server version string, which
// distributions and the server itself extend ("8.0.35-0ubuntu0.22.04.1",
// "5.7.33-log", Percona "8.0.35-27").
var mysqlUpstreamRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+`)

// productVersion applies the product-specific version conventions NVD's records
// assume: MariaDB's "5.5.5-" handshake prefix is dropped, and a MySQL server
// version is reduced to its upstream release (the build suffix would otherwise
// sort above the release and fall outside Oracle's inclusive bounds).
func productVersion(p Product, v string) string {
	switch {
	case p.Product == "mariadb" && strings.HasPrefix(v, mariadbCompatPrefix):
		return NormalizeVersion(strings.TrimSuffix(strings.TrimPrefix(v, mariadbCompatPrefix), "-mariadb"))
	case p.Vendor == "mysql" || (p.Vendor == "oracle" && strings.HasPrefix(p.Product, "mysql")):
		if m := mysqlUpstreamRe.FindString(v); m != "" && len(m) < len(v) && v[len(m)] == '-' {
			return m
		}
	}
	return v
}

// PlatformSet is a set of operating-system families a CVE record is limited to
// (NVD's "running on" AND configurations), or that an observation runs on. A
// record limited to particular Linux distributions also carries their lineages.
type PlatformSet uint16

// Platform families.
const (
	PlatformWindows PlatformSet = 1 << iota
	PlatformLinux
	PlatformApple
	PlatformBSD
	PlatformOther // a platform outside the families above: never contradicted
)

// Linux distribution lineages. A record carries them only when every Linux
// platform it names is a known distribution (Alpine-only CVE-2026-123158); one
// naming the kernel or an unknown distribution applies to any Linux. A lineage
// groups the distributions that rebuild one another's packages, so a record is
// only ruled out by a distribution from another lineage: a Debian-limited record
// is kept on Ubuntu, a RHEL-limited one on Rocky Linux.
const (
	PlatformDebian PlatformSet = 1 << (iota + 8) // Debian, Ubuntu, Raspbian
	PlatformRedHat                               // RHEL, CentOS, Rocky, AlmaLinux, Fedora, Oracle and Amazon Linux
	PlatformSUSE                                 // SUSE Linux Enterprise, openSUSE
	PlatformAlpine                               // Alpine Linux (musl)
)

// platformUnix is what a generic "Unix" says: some non-Windows system.
const platformUnix = PlatformLinux | PlatformApple | PlatformBSD

// platformDistros masks the distribution lineages.
const platformDistros = PlatformDebian | PlatformRedHat | PlatformSUSE | PlatformAlpine

var platformNames = []struct {
	bit  PlatformSet
	name string
}{
	{PlatformWindows, "windows"}, {PlatformLinux, "linux"}, {PlatformApple, "apple"}, {PlatformBSD, "bsd"}, {PlatformOther, "other"},
	{PlatformDebian, "debian"}, {PlatformRedHat, "redhat"}, {PlatformSUSE, "suse"}, {PlatformAlpine, "alpine"},
}

// Names lists the families in the set. Distribution lineages stand in for
// "linux" when the set has them: a record limited to Alpine is "alpine".
func (s PlatformSet) Names() []string {
	var out []string
	for _, f := range platformNames {
		if s&f.bit != 0 && (f.bit != PlatformLinux || s&platformDistros == 0) {
			out = append(out, f.name)
		}
	}
	return out
}

// platformOf maps a platform CPE to its family, plus its lineage for a known
// Linux distribution.
func platformOf(c CPE) PlatformSet {
	switch {
	case c.Vendor == "microsoft" && strings.HasPrefix(c.Product, "windows"):
		return PlatformWindows
	case strings.Contains(c.Product, "linux") || c.Product == "fedora" || c.Product == "centos" || c.Product == "almalinux" ||
		c.Vendor == "suse" || c.Vendor == "opensuse":
		return PlatformLinux | distroLineageOfCPE(c)
	case c.Vendor == "apple" && (c.Product == "mac_os_x" || c.Product == "macos" || c.Product == "iphone_os" || c.Product == "ipados"):
		return PlatformApple
	case c.Product == "freebsd" || c.Product == "openbsd" || c.Product == "netbsd":
		return PlatformBSD
	}
	return PlatformOther
}

// distroLineageOfCPE returns the lineage of a Linux distribution's OS CPE, 0 for
// the kernel or a distribution outside the lineages.
func distroLineageOfCPE(c CPE) PlatformSet {
	switch {
	case c.Vendor == "debian" && c.Product == "debian_linux", c.Vendor == "canonical" && c.Product == "ubuntu_linux",
		c.Product == "raspbian":
		return PlatformDebian
	case c.Vendor == "redhat" && (strings.HasPrefix(c.Product, "enterprise_linux") || c.Product == "linux"),
		c.Vendor == "centos" && c.Product == "centos", c.Vendor == "fedoraproject" && c.Product == "fedora",
		c.Product == "rocky_linux", c.Product == "almalinux", c.Vendor == "oracle" && c.Product == "linux",
		c.Vendor == "amazon" && (c.Product == "linux" || c.Product == "amazon_linux" || strings.HasPrefix(c.Product, "linux_")):
		return PlatformRedHat
	case c.Vendor == "suse" || c.Vendor == "opensuse" || c.Vendor == "novell" && strings.Contains(c.Product, "suse"):
		return PlatformSUSE
	case c.Vendor == "alpinelinux" && c.Product == "alpine_linux":
		return PlatformAlpine
	}
	return 0
}

// distroLineage returns the lineage of a distribution name DetectDistro reports.
func distroLineage(distro string) PlatformSet {
	switch distro {
	case "debian", "ubuntu", "raspbian":
		return PlatformDebian
	case "rhel", "centos", "rocky", "almalinux", "fedora", "amazon":
		return PlatformRedHat
	case "suse":
		return PlatformSUSE
	case "alpine":
		return PlatformAlpine
	}
	return 0
}

var (
	windowsTextRe = regexp.MustCompile(`windows|win32|win64|microsoft-iis|\biis\b`)
	unixTextRe    = regexp.MustCompile(`\bunix\b|linux`)
)

// observedPlatform derives the OS family a service runs on from its OS CPEs, the
// detected distribution and its banner text; 0 when nothing says. It never holds
// a distribution lineage: the distribution itself is matched by contradicts.
func observedPlatform(osCPEs []CPE, distro string, texts ...string) PlatformSet {
	for _, c := range osCPEs {
		if f := platformOf(c) &^ platformDistros; f != PlatformOther {
			return f
		}
	}
	switch distro {
	case "":
	case "freebsd":
		return PlatformBSD
	default:
		return PlatformLinux
	}
	all := strings.ToLower(strings.Join(texts, " "))
	switch {
	case windowsTextRe.MatchString(all):
		return PlatformWindows
	case unixTextRe.MatchString(all):
		return platformUnix
	}
	return 0
}

// contradicts reports whether a record limited to the platforms in rec cannot
// apply to a service observed on obs, built by distro (the DetectDistro name, ""
// when unknown): its family is not one of the record's, or it is a Linux service
// from a distribution lineage the record does not name.
func contradicts(rec, obs PlatformSet, distro string) bool {
	fam := rec &^ platformDistros
	if fam != 0 && obs != 0 && fam&PlatformOther == 0 && fam&obs == 0 {
		return true
	}
	if d := rec & platformDistros; d != 0 && obs&PlatformLinux != 0 {
		if l := distroLineage(distro); l != 0 && d&l == 0 {
			return true
		}
	}
	return false
}

// conditional reports whether a record limited to rec applies to the observation
// only under a condition it could not check: the platform is unknown, or the
// record names Linux distributions and the service's distribution is unknown.
func conditional(rec, obs PlatformSet, distro string) bool {
	if rec == 0 {
		return false
	}
	return obs == 0 || rec&platformDistros != 0 && obs&PlatformLinux != 0 && distroLineage(distro) == 0
}

// mariadbCompatPrefix is the "5.5.5-" MariaDB puts before its real version in the
// MySQL handshake for old-client compatibility ("5.5.5-10.3.39-MariaDB").
const mariadbCompatPrefix = "5.5.5-"

// distroPatterns names the distributions whose packages routinely backport
// security fixes without changing the upstream version. Order matters: the first
// match wins, so the more specific names come first.
var distroPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"raspbian", regexp.MustCompile(`raspbian`)},
	{"ubuntu", regexp.MustCompile(`ubuntu`)},
	{"debian", regexp.MustCompile(`debian|\+deb[0-9]|deb[0-9]+u[0-9]+`)},
	{"rocky", regexp.MustCompile(`rocky`)},
	{"almalinux", regexp.MustCompile(`almalinux`)},
	{"centos", regexp.MustCompile(`centos`)},
	{"rhel", regexp.MustCompile(`red ?hat|rhel|\.el[0-9]+`)},
	{"fedora", regexp.MustCompile(`fedora|\.fc[0-9]+`)},
	{"suse", regexp.MustCompile(`suse|sles`)},
	{"alpine", regexp.MustCompile(`alpine`)},
	{"amazon", regexp.MustCompile(`amzn|amazon linux`)},
	{"freebsd", regexp.MustCompile(`freebsd`)},
}

// DetectDistro reports the distribution a service's build comes from, from its
// version string, nmap extra info or Server header comment. It returns "" when
// none is recognized. The result is always one of a fixed set of names.
func DetectDistro(texts ...string) string {
	all := strings.ToLower(strings.Join(texts, " "))
	if all == "" {
		return ""
	}
	for _, d := range distroPatterns {
		if d.re.MatchString(all) {
			return d.name
		}
	}
	return ""
}

// distroFromOSCPE maps an operating-system CPE that nmap attaches to a service
// (e.g. cpe:/o:canonical:ubuntu_linux) to a distribution name, "" otherwise.
func distroFromOSCPE(c CPE) string {
	switch c.Vendor + ":" + c.Product {
	case "canonical:ubuntu_linux":
		return "ubuntu"
	case "debian:debian_linux":
		return "debian"
	case "redhat:enterprise_linux", "redhat:linux":
		return "rhel"
	case "centos:centos":
		return "centos"
	case "fedoraproject:fedora":
		return "fedora"
	case "suse:linux_enterprise_server", "opensuse:leap", "novell:suse_linux":
		return "suse"
	case "alpinelinux:alpine_linux":
		return "alpine"
	case "amazon:linux", "amazon:amazon_linux":
		return "amazon"
	case "freebsd:freebsd":
		return "freebsd"
	}
	return ""
}

// CompareVersions compares two dotted/alphanumeric version strings and returns
// -1, 0, or +1. It tokenizes each version into numeric and alphabetic runs
// (so "8.2p1" -> [8, 2, "p", 1]) and compares token by token: numeric tokens
// compare as integers and sort below alphabetic tokens of the same position; a
// missing token sorts below a present one (so "1.0" < "1.0.1"). It is a loose,
// total order good enough to place a version inside an inclusive/exclusive range;
// it is not a full SemVer / RPM evr comparator.
func CompareVersions(a, b string) int {
	return compareTokens(versionTokens(a), versionTokens(b))
}

func compareTokens(ta, tb []token) int {
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if i >= len(ta) {
			return -1
		}
		if i >= len(tb) {
			return 1
		}
		if c := compareToken(ta[i], tb[i]); c != 0 {
			return c
		}
	}
	return 0
}

// token is one run of a version string: numeric (isNum) or alphabetic (text).
type token struct {
	num   int
	text  string
	isNum bool
}

func versionTokens(v string) []token {
	v = strings.ToLower(strings.TrimSpace(v))
	var out []token
	i := 0
	for i < len(v) {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(v[i:j])
			if err != nil {
				n = int(^uint(0) >> 1) // an absurdly long run sorts last, never wraps
			}
			out = append(out, token{num: n, isNum: true})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, token{text: v[i:j]})
			i = j
		default:
			i++ // separators split tokens
		}
	}
	return out
}

func compareToken(a, b token) int {
	switch {
	case a.isNum && b.isNum:
		switch {
		case a.num < b.num:
			return -1
		case a.num > b.num:
			return 1
		}
		return 0
	case a.isNum:
		return -1 // 1.0 < 1.0a : a numeric token precedes an alpha token
	case b.isNum:
		return 1
	}
	return strings.Compare(a.text, b.text)
}
