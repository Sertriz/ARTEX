package cvematch

import "strings"

// Canonical maps a vendor:product pair as observed (nmap still emits several
// vendor names NVD has since renamed, e.g. igor_sysoev:nginx) to the pairs NVD
// uses. A pair absent from the table maps to itself.
func Canonical(p Product) []Product {
	if ps, ok := cpeAliases[p.key()]; ok {
		return ps
	}
	return []Product{p}
}

// AliasProducts maps a free product name (an nmap product string, an
// httpx/wappalyzer technology, a Server-header token) to the canonical NVD
// vendor:product pairs it denotes. It returns nil for an unknown name.
func AliasProducts(name string) []Product {
	return nameAliases[aliasKey(name)]
}

// aliasKey normalizes a product name for the alias table: lowercase, every run of
// characters other than letters and digits collapsed to one space.
func aliasKey(name string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			space = false
			continue
		}
		space = true
	}
	return b.String()
}

// aliasTable is one product: the NVD pairs, the stale pairs that denote it, and
// the names it is observed under.
type aliasTable struct {
	pairs []Product
	stale []Product
	names []string
}

var (
	nameAliases = map[string][]Product{}
	cpeAliases  = map[string][]Product{}
)

func init() {
	for _, t := range aliasData {
		// Every pair of a product, current or stale, reaches all of its current
		// pairs: a product NVD files under two vendors (a rename) must be looked up
		// under both, whichever of them the observation carried.
		for _, s := range append(append([]Product(nil), t.pairs...), t.stale...) {
			cpeAliases[s.key()] = t.pairs
		}
		for _, n := range t.names {
			if k := aliasKey(n); k != "" {
				nameAliases[k] = t.pairs
			}
		}
	}
}

func pp(pairs ...string) []Product {
	out := make([]Product, 0, len(pairs))
	for _, s := range pairs {
		v, p, _ := strings.Cut(s, ":")
		out = append(out, Product{Vendor: v, Product: p})
	}
	return out
}
