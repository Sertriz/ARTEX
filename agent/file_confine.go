package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
//   - never: the key files, the config file, the key directory when it holds
//     nothing else agents use, and the proxy CA store, even when a root contains
//     them.
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
// sets it once at startup with SetFileToolPolicy, which resolves every path in it
// then: later checks compare against those fixed paths and never follow a root
// through a symlink again, so a root replaced by a link later (or a name in the
// shared temp directory planted by another local user) widens nothing.
type FileToolPolicy struct {
	DataDir   string   // ARTEX data root (tasks/, sessions/, drafts/, noa/ live under it)
	SkillsDir string   // skills, readable only
	ReadDirs  []string // more read-only directories (the browser MCP's output directory)
	Deny      []string // files and directories never reachable (keys, config, the proxy CA store)
	Allow     []string // exact files inside Deny agents still read (the proxy CA certificates)

	rawDataDir string // DataDir as configured, to map run directories given in that form
	tempRoot   string // <tmp>/norma, the SDK's background-task output, when trustworthy
}

var fileToolPolicy atomic.Pointer[FileToolPolicy]

// SetFileToolPolicy installs the layout the file tools are confined to. Until it
// is called (unit tests that build agents directly) the tools are not confined.
// The data and skills directories are resolved as configured. The extra read
// directories and the SDK's temp-dir root must be directories this process owns
// and nobody else can write, or not exist yet; any other one is dropped.
func SetFileToolPolicy(p FileToolPolicy) {
	q := FileToolPolicy{rawDataDir: absClean(p.DataDir)}
	q.DataDir = resolvedOrClean(p.DataDir)
	q.SkillsDir = resolvedOrClean(p.SkillsDir)
	for _, d := range p.ReadDirs {
		if r, ok := trustedDir(d); ok {
			q.ReadDirs = append(q.ReadDirs, r)
		}
	}
	for _, d := range p.Deny {
		if r := resolvedOrClean(d); r != "" {
			q.Deny = append(q.Deny, r)
		}
	}
	for _, f := range p.Allow {
		if r := resolvedOrClean(f); r != "" {
			q.Allow = append(q.Allow, r)
		}
	}
	if r, ok := trustedDir(filepath.Join(os.TempDir(), "norma")); ok {
		q.tempRoot = r
	}
	fileToolPolicy.Store(&q)
}

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

// grepTreeLimit bounds the files and links the pre-search walk of a Grep tree
// inspects (directories are not counted).
const grepTreeLimit = 200000

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
	m, err := decodeToolInput(in)
	if err != nil {
		return nil, err
	}
	// encoding/json matches object keys to struct fields without regard to case,
	// so the tool would read "FILE_PATH" or "Path" as its path while a lookup of
	// the exact key saw none. Only the exact spelling is accepted.
	for k := range m {
		if k != field && strings.EqualFold(k, field) {
			return nil, fmt.Errorf("the path must be given as %q, not %q", field, k)
		}
	}
	raw, isStr := m[field].(string)
	if _, present := m[field]; present && !isStr {
		return nil, fmt.Errorf("%s must be a string", field)
	}
	wd := ""
	if tc != nil {
		wd = tc.WorkingDir
	}
	if strings.TrimSpace(raw) == "" {
		if field == "file_path" {
			return nil, errors.New("file_path is required")
		}
		raw = wd // LS, Glob and Grep default to the working directory
		if raw == "" {
			return nil, errors.New("no working directory for this run")
		}
	}
	run := p.runDir(wd)
	writable, readable := p.roots(run)
	allowed := readable
	if writingFileTools[name] {
		allowed = writable
	}
	real, err := p.confine(raw, wd, allowed, !writingFileTools[name])
	if err != nil {
		return nil, err
	}
	if name == "Grep" {
		glob, _ := m["glob"].(string)
		if err := p.checkTree(real, readable, glob); err != nil {
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

// decodeToolInput decodes a tool input object for the check. Anything the check
// cannot decode is refused rather than passed through: the tool decodes the same
// bytes into its own struct, which ignores fields the check would choke on (a
// number too large for a float64), so a pass-through would skip the check.
// Numbers are kept as written, and the input must be a single JSON object.
func decodeToolInput(in json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, errors.New("the input must be a JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the input must be a single JSON object")
	}
	return m, nil
}

// runDir returns the root a run's working directory stands for. A working
// directory inside the data root is mapped onto the data root resolved at
// install, without following links below it, so a run directory later replaced
// by a link does not move the root. Anything else is resolved as it is now.
func (p *FileToolPolicy) runDir(wd string) string {
	if wd == "" {
		return ""
	}
	abs := absClean(wd)
	if p.rawDataDir != "" && p.DataDir != "" && within(p.rawDataDir, abs) {
		rel, _ := filepath.Rel(p.rawDataDir, abs)
		return filepath.Join(p.DataDir, rel)
	}
	if p.DataDir != "" && within(p.DataDir, abs) {
		return abs
	}
	r, err := realPath(abs)
	if err != nil {
		return ""
	}
	return r
}

// roots returns the directories a run with root run may write and read.
// Writable roots are also readable.
func (p *FileToolPolicy) roots(run string) (writable, readable []string) {
	if run != "" {
		writable = append(writable, run)
		if td := p.taskDirOf(run); td != "" && td != run {
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
	if p.tempRoot != "" {
		readable = append(readable, p.tempRoot)
	}
	return writable, readable
}

// taskDirOf returns <data>/tasks/<id> when run lies inside it, else "".
func (p *FileToolPolicy) taskDirOf(run string) string {
	if p.DataDir == "" {
		return ""
	}
	tasks := filepath.Join(p.DataDir, "tasks")
	rel, err := filepath.Rel(tasks, run)
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
		if p.denied(real) {
			return "", fmt.Errorf("%s is outside the files this agent may access", raw)
		}
		if !underAny(real, roots) {
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
		if f == real {
			return true
		}
	}
	return false
}

// denied reports whether real is, or lies inside, a Deny path.
func (p *FileToolPolicy) denied(real string) bool {
	for _, d := range p.Deny {
		if within(d, real) {
			return true
		}
	}
	return false
}

// underAny reports whether real lies under one of roots, which are already
// resolved: a root is never followed through a link here.
func underAny(real string, roots []string) bool {
	for _, r := range roots {
		if r != "" && within(r, real) {
			return true
		}
	}
	return false
}

// grepSkippedByBoth are directories neither Grep backend searches (ripgrep skips
// hidden ones, the Go fallback skips these names).
var grepSkippedByBoth = map[string]bool{".git": true}

// grepSkippedByFallback are directories the Go fallback does not enter. Ripgrep
// does search them, but it never follows a link, so links inside them are read
// by neither backend.
var grepSkippedByFallback = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// checkTree walks a Grep search tree before the search and refuses it when the
// search would read something the path check did not see. It models what the
// two backends of the SDK's Grep read: ripgrep never follows a link, the Go
// fallback (used without ripgrep, or when ripgrep fails, which a file in the
// tree can cause) reads the target of every file link it meets, except inside
// .git, node_modules and vendor and except binary files. So the walk refuses:
//
//   - a tree holding a Deny path (the search would read it directly);
//   - a file link the fallback would read whose target is a text file outside the
//     readable roots or on the Deny list, or not a regular file;
//   - a hardlinked regular file anywhere but .git (both backends read it).
//
// Links to directories are not followed by either backend and are ignored.
func (p *FileToolPolicy) checkTree(root string, readable []string, glob string) error {
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil // a single file was checked by confine; a missing one fails in the tool
	}
	for _, d := range p.Deny {
		if d != root && within(root, d) {
			return fmt.Errorf("the search tree holds files this agent may not read (%s); search a narrower path", d)
		}
	}
	n := 0
	errTooLarge := errors.New("stop")
	var bad error
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && grepSkippedByBoth[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		n++
		if n > grepTreeLimit {
			return errTooLarge
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			if fallbackSkips(root, path) {
				return nil
			}
			if glob != "" {
				if ok, _ := filepath.Match(glob, d.Name()); !ok {
					return nil
				}
			}
			if err := p.checkTreeLink(path, readable); err != nil {
				bad = err
				return filepath.SkipAll
			}
		case d.Type().IsRegular():
			if hardlinked(path) {
				bad = fmt.Errorf("the search tree holds a hardlinked file (%s); search a narrower path", path)
				return filepath.SkipAll
			}
		}
		return nil
	})
	if errors.Is(walkErr, errTooLarge) {
		return fmt.Errorf("the search tree holds more than %d files; search a narrower path", grepTreeLimit)
	}
	return bad
}

// checkTreeLink judges one file link the Go fallback would read through.
func (p *FileToolPolicy) checkTreeLink(path string, readable []string) error {
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil // dangling: nothing to read through it
	}
	fi, err := os.Stat(r)
	if err != nil || fi.IsDir() {
		return nil // a directory is not read through a link
	}
	if !p.denied(r) && underAny(r, readable) && !hardlinked(r) {
		return nil
	}
	if fi.Mode().IsRegular() && !p.denied(r) && binaryHead(r) {
		return nil // the fallback skips binary files (a venv's python, a tool binary)
	}
	return fmt.Errorf("the search tree holds a link (%s) that leads outside the files this agent may access; search a narrower path", path)
}

// fallbackSkips reports whether path lies in a directory the Go fallback does
// not enter.
func fallbackSkips(root, path string) bool {
	rel, err := filepath.Rel(root, filepath.Dir(path))
	if err != nil || rel == "." {
		return false
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if grepSkippedByFallback[part] {
			return true
		}
	}
	return false
}

// binaryHead reports whether a regular file holds a NUL byte in its first 8000
// bytes, the SDK's own binary test (norma tool.isBinary). Only the head is read.
func binaryHead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8000)
	n, _ := io.ReadFull(f, buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
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

// absClean returns p absolute and cleaned, or "" for an empty p.
func absClean(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// resolvedOrClean returns the real path of p, or its clean absolute form when it
// cannot be resolved; "" for an empty p.
func resolvedOrClean(p string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	if r, err := realPath(p); err == nil {
		return r
	}
	return absClean(p)
}

// trustedDir resolves a root directory that a less trusted party might own or
// replace (a name in the shared temp directory, a working-directory subfolder).
// Its parent is resolved; the directory itself must not be a link, must be owned
// by this process's user and must not be writable by everyone. One that does not
// exist yet is kept as its literal path: whatever appears there later is judged
// file by file, and a link planted in its place leads outside it.
func trustedDir(dir string) (string, bool) {
	abs := absClean(dir)
	if abs == "" {
		return "", false
	}
	parent, err := realPath(filepath.Dir(abs))
	if err != nil {
		return "", false
	}
	r := filepath.Join(parent, filepath.Base(abs))
	fi, err := os.Lstat(r)
	if errors.Is(err, fs.ErrNotExist) {
		return r, true
	}
	if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || fi.Mode().Perm()&0o002 != 0 {
		return "", false
	}
	if uid, ok := fileOwner(fi); ok && uid != os.Geteuid() {
		return "", false
	}
	return r, true
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
// policy, and not be a hardlinked file. Each root goes through trustedDir. The
// resolved path is returned. With the confinement turned off the path is
// returned unchanged.
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
	var trusted []string
	for _, r := range roots {
		if t, ok := trustedDir(r); ok {
			trusted = append(trusted, t)
		}
	}
	return p.confine(path, "", trusted, false)
}

// ActiveFileToolPolicy returns the enforced policy, or nil when the confinement
// is off or not configured.
func ActiveFileToolPolicy() *FileToolPolicy { return activeFilePolicy() }
