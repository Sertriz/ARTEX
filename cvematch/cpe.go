// Package cvematch is an engine-side, non-AI, deterministic layer that turns a
// service's known product/version (or CPE) into candidate CVEs for the planner.
// It is a planning aid, not an exploit engine: it performs no network I/O, acts on
// nothing, and every CVE it emits is an UNVERIFIED lead that a worker must confirm.
//
// The matching is intentionally conservative about what counts as "the same
// product" (vendor+product from a CPE, or a normalized product name) and about
// version ranges, because a version match is a lead — banners lie, distributions
// backport fixes without bumping the version, and a CPE can be wrong.
package cvematch

import (
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

// key is the index key used by a Source: "vendor:product". With an empty vendor
// (product-only lookups) it is ":product".
func (p Product) key() string { return p.Vendor + ":" + p.Product }

// ParseCPE parses a CPE 2.2 URI ("cpe:/a:openbsd:openssh:8.2") or a CPE 2.3
// formatted string ("cpe:2.3:a:openbsd:openssh:8.2:*:*:...") and returns the
// vendor, product and (if present) version. ok is false when s is not a CPE.
//
// Only the application part ("a") and operating-system part ("o") are accepted;
// hardware ("h") is ignored. "*" and "-" version fields are treated as absent.
func ParseCPE(s string) (prod Product, version string, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		return parseCPE23(s)
	case strings.HasPrefix(s, "cpe:/"):
		return parseCPE22(s)
	}
	return Product{}, "", false
}

// parseCPE23: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:...
func parseCPE23(s string) (Product, string, bool) {
	f := splitCPE23(s[len("cpe:2.3:"):])
	if len(f) < 4 {
		return Product{}, "", false
	}
	if f[0] != "a" && f[0] != "o" {
		return Product{}, "", false
	}
	vendor, product := cpeField(f[1]), cpeField(f[2])
	if vendor == "" && product == "" {
		return Product{}, "", false
	}
	version := ""
	if len(f) >= 4 {
		version = cpeVersion(f[3])
	}
	return Product{Vendor: vendor, Product: product}, version, true
}

// parseCPE22: cpe:/<part>:<vendor>:<product>:<version>:...
func parseCPE22(s string) (Product, string, bool) {
	f := strings.Split(s[len("cpe:/"):], ":")
	if len(f) < 3 {
		return Product{}, "", false
	}
	if f[0] != "a" && f[0] != "o" {
		return Product{}, "", false
	}
	vendor, product := cpeField(f[1]), cpeField(f[2])
	if vendor == "" && product == "" {
		return Product{}, "", false
	}
	version := ""
	if len(f) >= 4 {
		version = cpeVersion(f[3])
	}
	return Product{Vendor: vendor, Product: product}, version, true
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
	out = append(out, cur.String())
	return out
}

// cpeField unescapes a CPE 2.3 field and maps the wildcards "*" and "-" to "".
func cpeField(s string) string {
	if s == "*" || s == "-" || s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "\\", "")
}

// cpeVersion is cpeField for a version: wildcards and the literal "*"/"-" mean the
// CPE pins no single version.
func cpeVersion(s string) string {
	v := cpeField(s)
	if v == "*" || v == "-" {
		return ""
	}
	return v
}

// NormalizeProductName maps a free product/service name (an nmap product string, a
// service_name, a technology label) to a best-effort Product with an empty vendor,
// for product-only lookups. It lowercases, keeps letters, digits, '-', '_' and '.',
// and collapses whitespace to a single '_'. It returns an empty Product when nothing
// usable remains.
func NormalizeProductName(name string) Product {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return Product{}
	}
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
			// drop anything else (slashes, parens, etc.)
			prevSpace = false
		}
	}
	p := strings.Trim(b.String(), "_")
	if p == "" {
		return Product{}
	}
	return Product{Product: p}
}

// CompareVersions compares two dotted/alphanumeric version strings and returns
// -1, 0, or +1. It tokenizes each version into numeric and alphabetic runs
// (so "8.2p1" -> [8, 2, "p", 1]) and compares token by token: numeric tokens
// compare as integers and sort below alphabetic tokens of the same position; a
// missing token sorts below a present one (so "1.0" < "1.0.1"). It is a loose,
// total order good enough to place a version inside an inclusive/exclusive range;
// it is not a full SemVer / RPM evr comparator.
func CompareVersions(a, b string) int {
	ta, tb := versionTokens(a), versionTokens(b)
	for i := 0; i < len(ta) || i < len(tb); i++ {
		if i >= len(ta) {
			return -1 // a ran out first -> a is the shorter/earlier version
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

// token is one run of a version string: numeric (num set, isNum true) or
// alphabetic (text set).
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
			n, _ := strconv.Atoi(v[i:j])
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
			// separators ('.', '-', '_', '+', 'p' handled as alpha above) split tokens
			i++
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
		default:
			return 0
		}
	case a.isNum && !b.isNum:
		return -1 // 1.0 < 1.0a : a numeric token precedes an alpha token
	case !a.isNum && b.isNum:
		return 1
	default:
		return strings.Compare(a.text, b.text)
	}
}
