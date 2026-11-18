//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// confineLayout builds a data root, a skills dir, a key dir outside both, a CA
// store, a worker run dir and an outside directory, and installs the policy.
type confineLayout struct {
	data, skills, keys, ca, task, run, other, outside string
}

func newConfineLayout(t *testing.T) confineLayout {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := confineLayout{
		data:    filepath.Join(base, "data"),
		skills:  filepath.Join(base, "skills"),
		keys:    filepath.Join(base, "keys"),
		outside: filepath.Join(base, "outside"),
	}
	l.ca = filepath.Join(l.data, "traffic", "_ca")
	l.task = filepath.Join(l.data, "tasks", "7")
	l.run = filepath.Join(l.task, "i3")
	l.other = filepath.Join(l.data, "tasks", "8")
	for _, d := range []string{l.skills, l.keys, l.outside, l.ca, l.run, l.other, filepath.Join(l.data, "sessions", "conv-1")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(l.keys, "jwt.key"):                    "JWT-SECRET",
		filepath.Join(l.keys, "secret.key"):                 "AES-SECRET",
		filepath.Join(l.ca, "mitmproxy-ca.pem"):             "CA-PRIVATE-KEY",
		filepath.Join(l.ca, "mitmproxy-ca-cert.pem"):        "CA-CERT",
		filepath.Join(l.outside, "secret.txt"):              "OUTSIDE-SECRET",
		filepath.Join(l.data, "config.json"):                "DATA-ROOT-FILE",
		filepath.Join(l.run, "notes.txt"):                   "run notes",
		filepath.Join(l.task, "bbot", "output.json"):        "task file",
		filepath.Join(l.other, "out.txt"):                   "other task file",
		filepath.Join(l.skills, "recon", "SKILL.md"):        "skill body",
		filepath.Join(l.data, "sessions", "conv-1", "a.md"): "session file",
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prev := fileToolPolicy.Load()
	t.Cleanup(func() { fileToolPolicy.Store(prev) })
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "")
	SetFileToolPolicy(FileToolPolicy{
		DataDir:   l.data,
		SkillsDir: l.skills,
		Deny:      []string{l.keys, l.ca},
		Allow:     []string{filepath.Join(l.ca, "mitmproxy-ca-cert.pem")},
	})
	return l
}

func sdkTool(t *testing.T, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range actool.DefaultTools() {
		if tl.Name() == name {
			return confineFileTool(tl)
		}
	}
	t.Fatalf("no SDK tool %s", name)
	return nil
}

func callTool(t *testing.T, name, wd string, in map[string]any) actool.Result {
	t.Helper()
	raw, _ := json.Marshal(in)
	res, err := sdkTool(t, name).Call(context.Background(), raw, &actool.ToolContext{WorkingDir: wd})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func wantRefused(t *testing.T, what string, res actool.Result) {
	t.Helper()
	if !res.IsError || !strings.Contains(res.Flatten(), "refused") {
		t.Fatalf("%s: want a refusal, got %q", what, res.Flatten())
	}
	for _, leak := range []string{"JWT-SECRET", "AES-SECRET", "CA-PRIVATE-KEY", "OUTSIDE-SECRET", "DATA-ROOT-FILE"} {
		if strings.Contains(res.Flatten(), leak) {
			t.Fatalf("%s: refusal leaked %s: %q", what, leak, res.Flatten())
		}
	}
}

func wantOK(t *testing.T, what string, res actool.Result, contains string) {
	t.Helper()
	if res.IsError || !strings.Contains(res.Flatten(), contains) {
		t.Fatalf("%s: want success containing %q, got %q", what, contains, res.Flatten())
	}
}

func TestFileToolConfineRead(t *testing.T) {
	l := newConfineLayout(t)
	read := func(p string) actool.Result { return callTool(t, "Read", l.run, map[string]any{"file_path": p}) }

	wantOK(t, "own run file", read(filepath.Join(l.run, "notes.txt")), "run notes")
	wantOK(t, "relative path", read("notes.txt"), "run notes")
	wantOK(t, "task file", read(filepath.Join(l.task, "bbot", "output.json")), "task file")
	wantOK(t, "another task", read(filepath.Join(l.other, "out.txt")), "other task file")
	wantOK(t, "skill", read(filepath.Join(l.skills, "recon", "SKILL.md")), "skill body")
	wantOK(t, "session", read(filepath.Join(l.data, "sessions", "conv-1", "a.md")), "session file")
	wantOK(t, "CA certificate", read(filepath.Join(l.ca, "mitmproxy-ca-cert.pem")), "CA-CERT")

	wantRefused(t, "jwt.key", read(filepath.Join(l.keys, "jwt.key")))
	wantRefused(t, "secret.key", read(filepath.Join(l.keys, "secret.key")))
	wantRefused(t, "CA private key", read(filepath.Join(l.ca, "mitmproxy-ca.pem")))
	wantRefused(t, "outside", read(filepath.Join(l.outside, "secret.txt")))
	wantRefused(t, "data root file", read(filepath.Join(l.data, "config.json")))
	wantRefused(t, "dot-dot", read("../../../../keys/jwt.key"))
	wantRefused(t, "proc environ", read("/proc/self/environ"))
	wantRefused(t, "etc", read("/etc/passwd"))

	// A symlink planted in the run dir is followed before the check.
	if err := os.Symlink(filepath.Join(l.keys, "jwt.key"), filepath.Join(l.run, "k")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "symlink to a key", read(filepath.Join(l.run, "k")))
	if err := os.Symlink(l.outside, filepath.Join(l.run, "dirlink")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "through a directory symlink", read(filepath.Join(l.run, "dirlink", "secret.txt")))

	// A hardlink names the key's inode from inside the run dir: refused.
	if err := os.Link(filepath.Join(l.outside, "secret.txt"), filepath.Join(l.run, "hl.txt")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "hardlink", read(filepath.Join(l.run, "hl.txt")))
}

func TestFileToolConfineWrite(t *testing.T) {
	l := newConfineLayout(t)
	write := func(p, c string) actool.Result {
		return callTool(t, "Write", l.run, map[string]any{"file_path": p, "content": c})
	}

	wantOK(t, "new file in run dir", write(filepath.Join(l.run, "new", "x.txt"), "x"), "")
	wantOK(t, "task dir", write(filepath.Join(l.task, "uploads", "y.txt"), "y"), "")

	wantRefused(t, "another task", write(filepath.Join(l.other, "out.txt"), "z"))
	wantRefused(t, "skills", write(filepath.Join(l.skills, "recon", "SKILL.md"), "z"))
	wantRefused(t, "CA certificate", write(filepath.Join(l.ca, "mitmproxy-ca-cert.pem"), "z"))
	wantRefused(t, "key", write(filepath.Join(l.keys, "jwt.key"), "z"))
	wantRefused(t, "outside", write(filepath.Join(l.outside, "new.txt"), "z"))
	if _, err := os.Stat(filepath.Join(l.outside, "new.txt")); err == nil {
		t.Fatal("refused Write still created the file")
	}

	// A dangling symlink would create its target wherever it points.
	if err := os.Symlink(filepath.Join(l.outside, "planted.txt"), filepath.Join(l.run, "dangle")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "dangling symlink", write(filepath.Join(l.run, "dangle"), "z"))
	if _, err := os.Stat(filepath.Join(l.outside, "planted.txt")); err == nil {
		t.Fatal("write through a dangling symlink created its target")
	}

	edit := callTool(t, "Edit", l.run, map[string]any{"file_path": filepath.Join(l.keys, "jwt.key"), "old_string": "JWT", "new_string": "X"})
	wantRefused(t, "Edit of a key", edit)
	multi := callTool(t, "MultiEdit", l.run, map[string]any{"file_path": filepath.Join(l.outside, "secret.txt"), "edits": []any{map[string]any{"old_string": "OUTSIDE", "new_string": "X"}}})
	wantRefused(t, "MultiEdit outside", multi)
	if b, _ := os.ReadFile(filepath.Join(l.keys, "jwt.key")); string(b) != "JWT-SECRET" {
		t.Fatalf("key changed: %q", b)
	}
	wantOK(t, "Edit in run dir", callTool(t, "Edit", l.run, map[string]any{"file_path": "notes.txt", "old_string": "run", "new_string": "RUN"}), "")
}

func TestFileToolConfineListAndSearch(t *testing.T) {
	l := newConfineLayout(t)

	wantOK(t, "LS default", callTool(t, "LS", l.run, map[string]any{}), "notes.txt")
	wantRefused(t, "LS keys", callTool(t, "LS", l.run, map[string]any{"path": l.keys}))
	wantRefused(t, "LS root", callTool(t, "LS", l.run, map[string]any{"path": "/"}))
	wantRefused(t, "LS data root", callTool(t, "LS", l.run, map[string]any{"path": l.data}))
	wantOK(t, "Glob task", callTool(t, "Glob", l.run, map[string]any{"pattern": "**/*.json", "path": l.task}), "output.json")
	wantRefused(t, "Glob outside", callTool(t, "Glob", l.run, map[string]any{"pattern": "*", "path": l.outside}))

	wantOK(t, "Grep run dir", callTool(t, "Grep", l.run, map[string]any{"pattern": "notes", "output_mode": "content", "path": l.run}), "")
	wantRefused(t, "Grep keys", callTool(t, "Grep", l.run, map[string]any{"pattern": "SECRET", "path": l.keys}))
	wantRefused(t, "Grep proc", callTool(t, "Grep", l.run, map[string]any{"pattern": "KEY", "path": "/proc/self/environ"}))

	// The search tree holds a link to a key: the whole search is refused.
	if err := os.Symlink(filepath.Join(l.keys, "secret.key"), filepath.Join(l.run, "k")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "Grep tree with a symlink out", callTool(t, "Grep", l.run, map[string]any{"pattern": "SECRET", "output_mode": "content"}))
	os.Remove(filepath.Join(l.run, "k"))
	if err := os.Link(filepath.Join(l.outside, "secret.txt"), filepath.Join(l.run, "hl.txt")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "Grep tree with a hardlink", callTool(t, "Grep", l.run, map[string]any{"pattern": "SECRET", "output_mode": "content"}))
}

// A relative path needs a working directory; a chat run in its session dir
// writes there and nowhere in the task tree.
func TestFileToolConfineRunKinds(t *testing.T) {
	l := newConfineLayout(t)
	wantRefused(t, "relative without wd", callTool(t, "Read", "", map[string]any{"file_path": "notes.txt"}))
	conv := filepath.Join(l.data, "sessions", "conv-1")
	wantOK(t, "chat writes its session dir", callTool(t, "Write", conv, map[string]any{"file_path": "b.md", "content": "b"}), "")
	wantRefused(t, "chat writes a task", callTool(t, "Write", conv, map[string]any{"file_path": filepath.Join(l.task, "x"), "content": "b"}))
	// The planner runs in the task dir itself: it writes there.
	wantOK(t, "planner writes its task", callTool(t, "Write", l.task, map[string]any{"file_path": "plan.md", "content": "p"}), "")
}

// Off switch, and no policy installed: the tools are left as they were.
func TestFileToolConfineOff(t *testing.T) {
	l := newConfineLayout(t)
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "off")
	wantOK(t, "off", callTool(t, "Read", l.run, map[string]any{"file_path": filepath.Join(l.outside, "secret.txt")}), "OUTSIDE-SECRET")
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "")
	fileToolPolicy.Store(nil)
	wantOK(t, "no policy", callTool(t, "Read", l.run, map[string]any{"file_path": filepath.Join(l.outside, "secret.txt")}), "OUTSIDE-SECRET")
}

// Only the SDK file tools are wrapped; the wrapper is installed on every agent's
// tool list by AugmentTools.
func TestConfineFileToolSelection(t *testing.T) {
	for _, tl := range actool.DefaultTools() {
		_, wrapped := confineFileTool(tl).(*confinedTool)
		if _, want := confinedFileTools[tl.Name()]; wrapped != want {
			t.Errorf("%s: wrapped=%v", tl.Name(), wrapped)
		}
	}
	out, _, cleanup := AugmentTools(context.Background(), "worker", actool.DefaultTools())
	defer cleanup()
	n := 0
	for _, tl := range out {
		g, ok := tl.(*guardedTool)
		if !ok {
			t.Fatalf("%s: not panic-guarded", tl.Name())
		}
		if _, ok := g.CoreTool.(*confinedTool); ok {
			n++
		}
	}
	if n != len(confinedFileTools) {
		t.Fatalf("AugmentTools confined %d tools, want %d", n, len(confinedFileTools))
	}
}

func TestConfineAgentPath(t *testing.T) {
	l := newConfineLayout(t)
	td := l.task
	if _, err := ConfineAgentPath(filepath.Join(td, "bbot", "output.json"), td); err != nil {
		t.Fatalf("task file: %v", err)
	}
	for _, p := range []string{
		filepath.Join(l.other, "out.txt"),
		filepath.Join(l.keys, "jwt.key"),
		filepath.Join(l.ca, "mitmproxy-ca-cert.pem"), // readable by the file tools, not an ingest source
		filepath.Join(td, "..", "8", "out.txt"),
		"relative/output.json",
	} {
		if _, err := ConfineAgentPath(p, td); err == nil {
			t.Errorf("%s: want refusal", p)
		}
	}
	if err := os.Symlink(filepath.Join(l.keys, "jwt.key"), filepath.Join(td, "k.png")); err != nil {
		t.Fatal(err)
	}
	if _, err := ConfineAgentPath(filepath.Join(td, "k.png"), td); err == nil {
		t.Error("symlink to a key: want refusal")
	}
	// Without a policy the deny list is empty but the root still holds.
	fileToolPolicy.Store(nil)
	if _, err := ConfineAgentPath(filepath.Join(l.outside, "secret.txt"), td); err == nil {
		t.Error("no policy: the root must still hold")
	}
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "0")
	if p, err := ConfineAgentPath(filepath.Join(l.outside, "secret.txt"), td); err != nil || p != filepath.Join(l.outside, "secret.txt") {
		t.Errorf("off: got %q, %v", p, err)
	}
}

// Deny wins over a root that contains it (a skills or data dir set to a parent
// of the key directory), except for the exact Allow files, which are read-only.
func TestFileToolConfineDenyOverridesRoot(t *testing.T) {
	l := newConfineLayout(t)
	base := filepath.Dir(l.data)
	SetFileToolPolicy(FileToolPolicy{
		DataDir:   l.data,
		SkillsDir: base,
		Deny:      []string{l.keys, l.ca},
		Allow:     []string{filepath.Join(l.ca, "mitmproxy-ca-cert.pem")},
	})
	read := func(p string) actool.Result { return callTool(t, "Read", l.run, map[string]any{"file_path": p}) }
	wantOK(t, "under the wide root", read(filepath.Join(l.outside, "secret.txt")), "OUTSIDE-SECRET")
	wantRefused(t, "key under the wide root", read(filepath.Join(l.keys, "jwt.key")))
	wantRefused(t, "CA key under the wide root", read(filepath.Join(l.ca, "mitmproxy-ca.pem")))
	wantRefused(t, "LS of the CA store", callTool(t, "LS", l.run, map[string]any{"path": l.ca}))
	wantOK(t, "CA certificate", read(filepath.Join(l.ca, "mitmproxy-ca-cert.pem")), "CA-CERT")
	if err := os.Symlink(filepath.Join(l.keys, "secret.key"), filepath.Join(l.run, "k")); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, "Grep tree with a link to a denied key", callTool(t, "Grep", l.run, map[string]any{"pattern": "SECRET", "output_mode": "content"}))
}

// The tool decodes its input with encoding/json, which matches keys without
// regard to case and skips unknown fields unparsed: the check must not read the
// input differently.
func TestFileToolConfineInputForms(t *testing.T) {
	l := newConfineLayout(t)
	key := filepath.Join(l.keys, "jwt.key")
	raw := func(name, in string) actool.Result {
		t.Helper()
		res, err := sdkTool(t, name).Call(context.Background(), json.RawMessage(in), &actool.ToolContext{WorkingDir: l.run})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return res
	}
	for _, in := range []string{
		`{"FILE_PATH":"` + key + `"}`,
		`{"File_Path":"` + key + `"}`,
		`{"file_path":"notes.txt","FILE_PATH":"` + key + `"}`,
		`{"ﬁle_path":"` + key + `"}`, // not a fold of file_path, but must not slip through either
		`{"file_path":"` + key + `","x":1e999}`,
		`{"file_path":"` + key + `"} {"file_path":"notes.txt"}`,
		`{"file_path":["` + key + `"]}`,
		`{"file_path":""}`,
		`{}`,
		`[]`,
	} {
		res := raw("Read", in)
		if !res.IsError || strings.Contains(res.Flatten(), "JWT-SECRET") {
			t.Errorf("Read %s: want an error, got %q", in, res.Flatten())
		}
	}
	if res := raw("LS", `{"PATH":"`+l.keys+`"}`); !res.IsError || strings.Contains(res.Flatten(), "jwt.key") {
		t.Errorf("LS PATH: want a refusal, got %q", res.Flatten())
	}
	if res := raw("Grep", `{"pattern":"SECRET","Path":"`+l.keys+`","output_mode":"content"}`); !res.IsError || strings.Contains(res.Flatten(), "SECRET") {
		t.Errorf("Grep Path: want a refusal, got %q", res.Flatten())
	}
	// Numbers survive the rewrite as written.
	wantOK(t, "Read with offset", raw("Read", `{"file_path":"notes.txt","offset":1,"limit":5}`), "run notes")
}
