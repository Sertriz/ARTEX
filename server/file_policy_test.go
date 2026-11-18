package server

import (
	"path/filepath"
	"slices"
	"testing"
)

// The key files are always denied; the key directory as a whole only when it
// holds neither the data nor the skills (bare metal keeps both under the install
// directory, which is also the default key directory).
func TestFileToolPolicyFor(t *testing.T) {
	base := t.TempDir()
	data, skills := filepath.Join(base, "data"), filepath.Join(base, "skills")

	p := fileToolPolicyFor(nil, skills, data, base)
	for _, want := range []string{filepath.Join(base, "jwt.key"), filepath.Join(base, "secret.key"), filepath.Join(data, "jwt.key"), filepath.Join(data, "traffic", "_ca")} {
		if !slices.Contains(p.Deny, want) {
			t.Errorf("bare metal: %s not denied: %v", want, p.Deny)
		}
	}
	if slices.Contains(p.Deny, base) {
		t.Errorf("bare metal: the install directory must not be denied as a whole: %v", p.Deny)
	}

	keys := filepath.Join(base, "keys")
	p = fileToolPolicyFor(nil, skills, data, keys)
	if !slices.Contains(p.Deny, keys) {
		t.Errorf("separate key dir not denied: %v", p.Deny)
	}
	if p.DataDir != data || p.SkillsDir != skills {
		t.Errorf("roots: %+v", p)
	}
}
