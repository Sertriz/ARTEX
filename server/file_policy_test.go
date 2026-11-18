package server

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func resolvedTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The key files are always denied; the key directory as a whole only when it
// holds neither the data nor the skills (bare metal keeps both under the install
// directory, which is also the default key directory).
func TestFileToolPolicyFor(t *testing.T) {
	t.Setenv("PLAYWRIGHT_MCP_OUTPUT_DIR", "")
	t.Chdir(resolvedTemp(t))
	base := resolvedTemp(t)
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

// The key directory is the working directory (ARTEX started from the directory
// that holds its keys, with the data elsewhere): the browser MCP saves into
// .playwright-mcp under it, so it is not denied as a whole; the key files are.
func TestFileToolPolicyKeyDirIsWorkingDir(t *testing.T) {
	t.Setenv("PLAYWRIGHT_MCP_OUTPUT_DIR", "")
	kd := resolvedTemp(t)
	t.Chdir(kd)
	data, skills := filepath.Join(resolvedTemp(t), "data"), filepath.Join(resolvedTemp(t), "skills")

	p := fileToolPolicyFor(nil, skills, data, kd)
	if slices.Contains(p.Deny, kd) {
		t.Errorf("key dir that is the working directory denied as a whole: %v", p.Deny)
	}
	for _, want := range []string{filepath.Join(kd, "jwt.key"), filepath.Join(kd, "secret.key")} {
		if !slices.Contains(p.Deny, want) {
			t.Errorf("%s not denied: %v", want, p.Deny)
		}
	}
	if !slices.Contains(p.ReadDirs, filepath.Join(kd, ".playwright-mcp")) {
		t.Errorf("browser output under the working directory not readable: %v", p.ReadDirs)
	}
}

// Containment is judged on resolved paths: a data directory configured through a
// link that leads into the key directory keeps the key directory open (only the
// key files are denied), and a browser output directory set to a parent of the
// data or the keys is not read at all.
func TestFileToolPolicyResolvedContainment(t *testing.T) {
	t.Setenv("PLAYWRIGHT_MCP_OUTPUT_DIR", "")
	t.Chdir(resolvedTemp(t))
	kd := resolvedTemp(t)
	if err := os.MkdirAll(filepath.Join(kd, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(resolvedTemp(t), "data")
	if err := os.Symlink(filepath.Join(kd, "data"), link); err != nil {
		t.Fatal(err)
	}
	p := fileToolPolicyFor(nil, filepath.Join(resolvedTemp(t), "skills"), link, kd)
	if slices.Contains(p.Deny, kd) {
		t.Errorf("key dir holding the linked data dir denied as a whole: %v", p.Deny)
	}
	if !slices.Contains(p.Deny, filepath.Join(kd, "jwt.key")) {
		t.Errorf("jwt.key not denied: %v", p.Deny)
	}

	for _, wide := range []string{filepath.Dir(kd), kd} {
		t.Setenv("PLAYWRIGHT_MCP_OUTPUT_DIR", wide)
		p = fileToolPolicyFor(nil, "", link, kd)
		if slices.Contains(p.ReadDirs, wide) {
			t.Errorf("browser output dir %s holds the keys or data but is readable: %v", wide, p.ReadDirs)
		}
	}
}
