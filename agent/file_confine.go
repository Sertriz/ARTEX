package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	actool "github.com/Autumn-27/norma/tool"
)

// File-tool confinement.
//
// The SDK file tools (Read, Write, Edit, MultiEdit, LS, Glob, Grep) run inside the
// ARTEX process, as its user, and accept any absolute path, "../" and symlinks.
// An agent steered by target content could read ARTEX's own keys (jwt.key mints
// admin tokens, secret.key decrypts every stored secret), the proxy CA private
// key or /proc, or rewrite files outside its run. confineFileTool limits each of
// those tools to the directories an agent's work needs:
//
//   - write: its own run directory, and for a task run the whole task directory
//     (bbot and rea output, uploads);
//   - read: the task, session, draft-upload and noa directories under the data
//     root, the skills directory, the SDK's background-task output directory, the
//     browser MCP's output directory, and the proxy CA certificate (never the CA
//     private key);
//   - never: the key files, the key directory when it holds nothing else agents
//     use, and the proxy CA store, even when a root contains them.
//
// The check runs on the resolved path (symlinks followed), refuses dangling
// symlinks and hardlinked files, and Grep additionally refuses a search tree that
// holds a link leading outside. The path passed on to the tool is the resolved
// one. This does not confine Bash: shell commands still run as the ARTEX user.
// It closes the in-process channel, which the approval rules and the judge never
// see, and is the half of the confinement that a separate agent UID cannot give.
//
// On by default; ARTEX_FILE_TOOL_CONFINE=0 (or false/off/no) turns it off.

// FileToolPolicy is the host layout the confinement is derived from. The server
// sets it once at startup with SetFileToolPolicy.
type FileToolPolicy struct {
	DataDir   string   // ARTEX data root (tasks/, sessions/, drafts/, noa/ live under it)
	SkillsDir string   // skills, readable only
	ReadDirs  []string // more read-only directories (the browser MCP's output directory)
	Deny      []string // files and directories never reachable (keys, the proxy CA store)
	Allow     []string // exact files inside Deny agents still read (the proxy CA certificates)
}

var fileToolPolicy atomic.Pointer[FileToolPolicy]

// SetFileToolPolicy installs the layout the file tools are confined to. Until it
// is called (unit tests that build agents directly) the tools are not confined.
func SetFileToolPolicy(p FileToolPolicy) { fileToolPolicy.Store(&p) }

// FileToolConfineEnabled reports whether ARTEX_FILE_TOOL_CONFINE leaves the
// confinement on (unset or empty = on).
func FileToolConfineEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_FILE_TOOL_CONFINE"))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// activeFilePolicy returns the policy to enforce, or nil when there is none.
func activeFilePolicy() *FileToolPolicy {
	p := fileToolPolicy.Load()
	if p == nil || !FileToolConfineEnabled() {
		return nil
	}
	return p
}

// confinedFileTools maps each confined SDK tool to its path field. Host tools
// cannot take these names (custom tool keys are lowercase, MCP tools are
// prefixed mcp__), so a name match is an SDK tool.
var confinedFileTools = map[string]string{
	"Read": "file_path", "Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path",
	"LS": "path", "Glob": "path", "Grep": "path",
}

// writingFileTools change the file they are given.
var writingFileTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true}

// grepTreeLimit bounds the pre-search walk of a Grep tree.
const grepTreeLimit = 50000

// confineFileTool wraps a confined SDK file tool; any other tool is returned as is.
func confineFileTool(t actool.CoreTool) actool.CoreTool {
	if _, ok := confinedFileTools[t.Name()]; !ok {
		return t
	}
	return &confinedTool{CoreTool: t}
}

type confinedTool struct{ actool.CoreTool }

// Call checks the final input, after every hook has had its chance to rewrite
// it, and hands the tool the resolved path.
func (c *confinedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	p := activeFilePolicy()
	if p == nil {
		return c.CoreTool.Call(ctx, in, tc)
	}
	out, err := p.checkToolInput(c.Name(), in, tc)
	if err != nil {
		return actool.Errorf(c.Name() + " refused: " + err.Error()), nil
	}
	return c.CoreTool.Call(ctx, out, tc)
}

// checkToolInput validates the path argument of a confined tool and returns the
// input with that path replaced by its resolved form.
func (p *FileToolPolicy) checkToolInput(name string, in json.RawMessage, tc *actool.ToolContext) (json.RawMessage, error) {
	field := confinedFileTools[name]
	var m map[string]any
	if err := json.Unmarshal(in, &m); err != nil {
		return in, nil // the tool reports malformed input itself
	}
	raw, _ := m[field].(string)
	wd := ""
	if tc != nil {
		wd = tc.WorkingDir
	}
	if strings.TrimSpace(raw) == "" {
		if field == "file_path" {
			return in, nil // the tool reports the missing path itself
		}
		raw = wd // LS, Glob and Grep default to the working directory
		if raw == "" {
			return nil, errors.New("no working directory for this run")
		}
	}
	writable, readable := p.roots(wd)
	allowed := readable
	if writingFileTools[name] {
		allowed = writable
	}
	real, err := p.confine(raw, wd, allowed, !writingFileTools[name])
	if err != nil {
		return nil, err
	}
	if name == "Grep" {
		if err := p.checkTree(real, readable); err != nil {
			return nil, err
		}
	}
	m[field] = real
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// roots returns the directories a run with working directory wd may write and
// read. Writable roots are also readable.
func (p *FileToolPolicy) roots(wd string) (writable, readable []string) {
	if wd != "" {
		writable = append(writable, wd)
		if td := p.taskDirOf(wd); td != "" && td != wd {
			writable = append(writable, td)
		}
	}
	readable = append(readable, writable...)
	if p.DataDir != "" {
		for _, sub := range []string{"tasks", "sessions", "drafts", "noa"} {
			readable = append(readable, filepath.Join(p.DataDir, sub))
		}
	}
	if p.SkillsDir != "" {
		readable = append(readable, p.SkillsDir)
	}
	readable = append(readable, p.ReadDirs...)
	// Background Bash and Monitor output (norma writes <tmp>/norma/<session>/tasks/*.output
	// and points the model at it).
	readable = append(readable, filepath.Join(os.TempDir(), "norma"))
	return writable, readable
}

// taskDirOf returns <data>/tasks/<id> when wd lies inside it, else "".
func (p *FileToolPolicy) taskDirOf(wd string) string {
	if p.DataDir == "" {
		return ""
	}
	tasks := filepath.Join(p.DataDir, "tasks")
	rel, err := filepath.Rel(tasks, wd)
	if err != nil || rel == "." || !isLocalRel(rel) {
		return ""
	}
	return filepath.Join(tasks, strings.Split(rel, string(filepath.Separator))[0])
}

// TaskDir returns the task directory <data>/tasks/<id>, or "" without a data root.
func (p *FileToolPolicy) TaskDir(taskID int64) string {
	if p == nil || p.DataDir == "" || taskID <= 0 {
		return ""
	}
	return filepath.Join(p.DataDir, "tasks", fmt.Sprint(taskID))
}

// confine resolves raw (absolute, or relative to wd) and returns its real path
// when that lies under one of roots and outside the Deny paths. A read (read
// true) may also name one of the exact Allow files.
func (p *FileToolPolicy) confine(raw, wd string, roots []string, read bool) (string, error) {
	target := raw
	if !filepath.IsAbs(target) {
		if wd == "" {
			return "", errors.New("relative path without a working directory")
		}
		target = filepath.Join(wd, target)
	}
	real, err := realPath(target)
	if err != nil {
		return "", err
	}
	extra := read && p.allowed(real) // a proxy CA certificate: read-only, wherever it lies
	if !extra {
		for _, d := range p.Deny {
			if rd, err := realPath(d); err == nil && within(rd, real) {
				return "", fmt.Errorf("%s is outside the files this agent may access", raw)
			}
		}
		if !p.underAny(real, roots) {
			return "", fmt.Errorf("%s is outside the files this agent may access (its run directory and the task, session and skill files)", raw)
		}
	}
	if hardlinked(real) {
		return "", fmt.Errorf("%s is a hardlinked file", raw)
	}
	return real, nil
}

// allowed reports whether real is one of the exact Allow files.
func (p *FileToolPolicy) allowed(real string) bool {
	for _, f := range p.Allow {
		if rf, err := realPath(f); err == nil && rf == real {
			return true
		}
	}
	return false
}

func (p *FileToolPolicy) underAny(real string, roots []string) bool {
	for _, r := range roots {
		if rr, err := realPath(r); err == nil && within(rr, real) {
			return true
		}
	}
	return false
}

// checkTree walks a Grep search tree and refuses it when a symlink in it leads
// outside the readable roots or a regular file in it is hardlinked: the search
// reads through both, and the path check only saw the tree's root.
func (p *FileToolPolicy) checkTree(root string, readable []string) error {
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil // a single file was checked by confine; a missing one fails in the tool
	}
	n := 0
	errTooLarge := errors.New("stop")
	var bad error
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		n++
		if n > grepTreeLimit {
			return errTooLarge
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			r, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil // dangling: nothing to read through it
			}
			if _, err := p.confine(r, "", readable, true); err != nil {
				bad = fmt.Errorf("the search tree holds a link (%s) that leads outside the files this agent may access", path)
				return filepath.SkipAll
			}
		case d.Type().IsRegular():
			if hardlinked(path) {
				bad = fmt.Errorf("the search tree holds a hardlinked file (%s)", path)
				return filepath.SkipAll
			}
		}
		return nil
	})
	if errors.Is(walkErr, errTooLarge) {
		return fmt.Errorf("the search tree holds more than %d entries; search a narrower path", grepTreeLimit)
	}
	return bad
}

// realPath returns the absolute, symlink-free form of p. Components that do not
// exist yet (a file Write is about to create) are kept as given after the
// deepest existing ancestor is resolved. A dangling symlink on the way is
// refused: writing through it would create its target, wherever that is.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cur, rest := abs, ""
	for {
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(r, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s cannot be resolved", p)
		}
		if fi, lerr := os.Lstat(cur); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("%s goes through a dangling symlink", p)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("%s cannot be resolved", p)
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// within reports whether path is root or lies below it. Both must be clean and
// absolute.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || isLocalRel(rel))
}

func isLocalRel(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// hardlinked reports whether path is a regular file with more than one link. A
// hardlink inside an allowed directory can name any file on the same filesystem,
// so a symlink check alone does not stop it.
func hardlinked(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode().IsRegular() && linkCount(fi) > 1
}

// ConfineAgentPath resolves an agent-supplied path for an in-process reader that
// is not an SDK file tool (ingest_bbot, ask_operator's image): it must be
// absolute, lie under one of roots, stay outside the Deny paths of the installed
// policy, and not be a hardlinked file. The resolved path
// is returned. With the confinement turned off the path is returned unchanged.
func ConfineAgentPath(path string, roots ...string) (string, error) {
	if !FileToolConfineEnabled() {
		return path, nil
	}
	p := fileToolPolicy.Load()
	if p == nil {
		p = &FileToolPolicy{}
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	return p.confine(path, "", roots, false)
}

// ActiveFileToolPolicy returns the enforced policy, or nil when the confinement
// is off or not configured.
func ActiveFileToolPolicy() *FileToolPolicy { return activeFilePolicy() }
