//go:build !windows

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func writeFile(t *testing.T, path, content string, dirMode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The SDK's background-task output root, <tmp>/norma, is a name in the shared
// temp directory that another local user can take first. It is read only when
// this user owns it and nobody else can write it, and it is never followed
// through a link, whether the link was planted before the policy was installed
// or after. The same holds for the extra read directories.
func TestFileToolConfineTempRoot(t *testing.T) {
	l := newConfineLayout(t)
	install := func(readDirs ...string) {
		t.Helper()
		SetFileToolPolicy(FileToolPolicy{DataDir: l.data, SkillsDir: l.skills, ReadDirs: readDirs, Deny: []string{l.keys, l.ca}})
	}
	read := func(p string) actool.Result { return callTool(t, "Read", l.run, map[string]any{"file_path": p}) }

	// Owned by this user and private: background output is readable.
	tmp := resolvedTempDir(t)
	t.Setenv("TMPDIR", tmp)
	out := filepath.Join(tmp, "norma", "sess", "tasks", "b1.output")
	writeFile(t, out, "bg output", 0o700)
	install()
	wantOK(t, "background output", read(out), "bg output")
	wantRefused(t, "temp dir beside the root", read(filepath.Join(tmp, "x")))

	// A link in place of the root before the policy is installed.
	tmp = resolvedTempDir(t)
	t.Setenv("TMPDIR", tmp)
	if err := os.Symlink(l.outside, filepath.Join(tmp, "norma")); err != nil {
		t.Fatal(err)
	}
	install()
	wantRefused(t, "root planted as a link", read(filepath.Join(tmp, "norma", "secret.txt")))

	// The root did not exist at install; a link put there later leads outside it.
	tmp = resolvedTempDir(t)
	t.Setenv("TMPDIR", tmp)
	install()
	if err := os.Symlink(l.outside, filepath.Join(tmp, "norma")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "root linked after install", read(filepath.Join(tmp, "norma", "secret.txt")))

	// A root everyone can write is not trusted.
	tmp = resolvedTempDir(t)
	t.Setenv("TMPDIR", tmp)
	ww := filepath.Join(tmp, "norma")
	writeFile(t, filepath.Join(ww, "s", "tasks", "b.output"), "planted", 0o700)
	if err := os.Chmod(ww, 0o777); err != nil {
		t.Fatal(err)
	}
	install()
	wantRefused(t, "world-writable root", read(filepath.Join(ww, "s", "tasks", "b.output")))

	// Extra read directories pass the same check.
	shots := filepath.Join(resolvedTempDir(t), "shots")
	writeFile(t, filepath.Join(shots, "page.png"), "png", 0o755)
	install(shots)
	wantOK(t, "owned read dir", read(filepath.Join(shots, "page.png")), "png")
	if err := os.Chmod(shots, 0o777); err != nil {
		t.Fatal(err)
	}
	install(shots)
	wantRefused(t, "world-writable read dir", read(filepath.Join(shots, "page.png")))
	linked := filepath.Join(resolvedTempDir(t), "shots")
	if err := os.Symlink(l.outside, linked); err != nil {
		t.Fatal(err)
	}
	install(linked)
	wantRefused(t, "read dir that is a link", read(filepath.Join(linked, "secret.txt")))

	// Owned by someone else (only root can set that up).
	if os.Geteuid() == 0 {
		other := filepath.Join(resolvedTempDir(t), "shots")
		writeFile(t, filepath.Join(other, "page.png"), "png", 0o755)
		if err := os.Chown(other, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		install(other)
		wantRefused(t, "read dir owned by another user", read(filepath.Join(other, "page.png")))
	}
}

// Grep's Go fallback reads through the file links in its tree, but not binary
// files and not inside node_modules, vendor or .git; ripgrep follows no link at
// all, and neither backend follows a link to a directory. A tree with only such
// links (a virtualenv, a node_modules link farm) is searched, without the search
// reading anything outside; a text-file link leading outside refuses the search.
// Both backends are run (the Go one alone when ripgrep is not installed).
func TestFileToolConfineGrepTreeLinks(t *testing.T) {
	for _, backend := range []string{"default", "go"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "go" {
				t.Setenv("NORMA_DISABLE_RIPGREP", "1")
			}
			l := newConfineLayout(t)
			bin := filepath.Join(l.outside, "python3")
			if err := os.WriteFile(bin, []byte("\x7fELF\x00\x00 OUTSIDE-SECRET in a binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			links := map[string]string{
				filepath.Join(l.run, "venv", "bin", "python"):               bin,
				filepath.Join(l.run, "venv", "lib64"):                       l.outside,
				filepath.Join(l.run, "node_modules", "pkg", "secret.txt"):   filepath.Join(l.outside, "secret.txt"),
				filepath.Join(l.run, "vendor", "x", "secret.txt"):           filepath.Join(l.outside, "secret.txt"),
				filepath.Join(l.run, "src", "node_modules", "y", "key.txt"): filepath.Join(l.keys, "jwt.key"),
			}
			for link, target := range links {
				if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			grep := func(in map[string]any) actool.Result {
				in["pattern"], in["output_mode"] = "SECRET", "content"
				return callTool(t, "Grep", l.run, in)
			}
			res := grep(map[string]any{})
			wantOK(t, "tree with venv and node_modules links", res, "")
			for _, leak := range []string{"OUTSIDE-SECRET", "JWT-SECRET"} {
				if strings.Contains(res.Flatten(), leak) {
					t.Fatalf("search read through a link: %q", res.Flatten())
				}
			}

			// A text file outside, linked from the tree.
			if err := os.Symlink(filepath.Join(l.outside, "secret.txt"), filepath.Join(l.run, "notes-link.txt")); err != nil {
				t.Fatal(err)
			}
			wantRefused(t, "tree with a text link out", grep(map[string]any{}))
			// The fallback applies the glob to the link's own name: one the glob
			// leaves out is never read.
			wantOK(t, "glob that leaves the link out", grep(map[string]any{"glob": "*.md"}), "")
			wantRefused(t, "glob that takes the link in", grep(map[string]any{"glob": "*.txt"}))
		})
	}
}

// Git hardlinks objects between clones and packs; neither backend searches .git,
// so hardlinks there do not refuse a search. One anywhere else still does.
func TestFileToolConfineGrepGitHardlinks(t *testing.T) {
	l := newConfineLayout(t)
	pack := filepath.Join(l.run, "repo", ".git", "objects", "pack")
	writeFile(t, filepath.Join(pack, "a.pack"), "pack", 0o755)
	if err := os.Link(filepath.Join(pack, "a.pack"), filepath.Join(pack, "b.pack")); err != nil {
		t.Fatal(err)
	}
	wantOK(t, "hardlinks inside .git", callTool(t, "Grep", l.run, map[string]any{"pattern": "notes", "output_mode": "content"}), "run notes")
	if err := os.Link(filepath.Join(pack, "a.pack"), filepath.Join(l.run, "repo", "a.pack")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "hardlink outside .git", callTool(t, "Grep", l.run, map[string]any{"pattern": "notes", "output_mode": "content"}))
}

// A Grep over a root wide enough to hold a Deny path would read it directly (no
// link involved): the search is refused, a narrower one is not.
func TestFileToolConfineGrepWideRoot(t *testing.T) {
	l := newConfineLayout(t)
	base := filepath.Dir(l.data)
	SetFileToolPolicy(FileToolPolicy{DataDir: l.data, SkillsDir: base, Deny: []string{l.keys, l.ca}})
	grep := func(path string) actool.Result {
		return callTool(t, "Grep", l.run, map[string]any{"pattern": "SECRET", "output_mode": "content", "path": path})
	}
	wantRefused(t, "root holding the keys", grep(base))
	wantRefused(t, "data root holding the CA store", grep(l.data))
	wantOK(t, "narrower path", grep(l.outside), "OUTSIDE-SECRET")
}

// A run directory given in the configured form of the data root is mapped onto
// the root resolved at install: replacing the run directory by a link later does
// not carry its write root along.
func TestFileToolConfineRunDirLink(t *testing.T) {
	l := newConfineLayout(t)
	base := filepath.Dir(l.data)
	alias := filepath.Join(base, "data-link")
	if err := os.Symlink(l.data, alias); err != nil {
		t.Fatal(err)
	}
	SetFileToolPolicy(FileToolPolicy{DataDir: alias, SkillsDir: l.skills, Deny: []string{l.keys, l.ca}})
	runAlias := filepath.Join(alias, "tasks", "7", "i3")
	wantOK(t, "write through the configured data path", callTool(t, "Write", runAlias, map[string]any{"file_path": "w.txt", "content": "w"}), "")

	// A worker run directory replaced by a link to outside after install.
	moved := filepath.Join(l.task, "i4")
	if err := os.Symlink(l.outside, moved); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "run dir replaced by a link", callTool(t, "Write", filepath.Join(alias, "tasks", "7", "i4"), map[string]any{"file_path": "planted.txt", "content": "x"}))
	if _, err := os.Stat(filepath.Join(l.outside, "planted.txt")); err == nil {
		t.Fatal("write through a linked run directory landed outside")
	}
}
