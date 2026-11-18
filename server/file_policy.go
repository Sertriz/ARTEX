package server

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
)

// installFileToolPolicy confines the agents' in-process file tools to this
// server's layout (agent.FileToolPolicy). dataDir is the root the run
// directories are made under (the Manager's, when there is one).
func installFileToolPolicy(m *Manager, skillDir, dataDir, keyDir string) {
	if m != nil && m.dir != "" {
		dataDir = m.dir
	}
	p := fileToolPolicyFor(m, skillDir, dataDir, keyDir)
	agent.SetFileToolPolicy(p)
	if agent.FileToolConfineEnabled() {
		log.Printf("[agent] file tools confined to the run, task, session and skill files (ARTEX_FILE_TOOL_CONFINE)")
	} else {
		log.Printf("[agent] WARNING: ARTEX_FILE_TOOL_CONFINE is off: agent file tools can read and write any file this process can, its keys included")
	}
}

// fileToolPolicyFor builds the policy. The Deny list holds:
//
//   - the key files (jwt.key mints admin tokens, secret.key decrypts every stored
//     secret), in the key directory and at the legacy data-dir location;
//   - the config file, which can hold the database password;
//   - the key directory itself, unless it also holds a directory agents use
//     (on bare metal it defaults to the install directory, which holds the data,
//     the skills or the browser MCP's output);
//   - the proxy CA store, whose private key signs certificates every client of
//     the proxy trusts. Its certificate files stay readable (Allow).
//
// Containment is judged on resolved paths.
func fileToolPolicyFor(m *Manager, skillDir, dataDir, keyDir string) agent.FileToolPolicy {
	p := agent.FileToolPolicy{DataDir: absPath(dataDir), SkillsDir: absPath(skillDir)}
	kd := ""
	if keyDir != "" {
		kd = resolvePath(keyDir)
	}
	for _, d := range browserOutputDirs() {
		// An output directory set to a parent of the data or the keys would open
		// all of it to the file tools; such a setting is not followed.
		if r := resolvePath(d); pathContains(r, resolvePath(p.DataDir)) || pathContains(r, kd) {
			log.Printf("[agent] browser output directory %s contains the data or key directory; agents' file tools will not read it", d)
			continue
		}
		p.ReadDirs = append(p.ReadDirs, d)
	}
	if kd != "" {
		p.Deny = append(p.Deny, filepath.Join(kd, jwtKeyFilename), filepath.Join(kd, db.SecretKeyFile))
		used := append([]string{p.DataDir, p.SkillsDir, workingDir()}, p.ReadDirs...)
		holdsUsed := false
		for _, u := range used {
			if u != "" && pathContains(kd, resolvePath(u)) {
				holdsUsed = true
				break
			}
		}
		if !holdsUsed {
			p.Deny = append(p.Deny, kd)
		}
	}
	if cfg := config.Path(); cfg != "" {
		p.Deny = append(p.Deny, absPath(cfg))
	}
	if p.DataDir != "" {
		p.Deny = append(p.Deny, filepath.Join(p.DataDir, jwtKeyFilename))
	}
	if m != nil && m.traffic != nil {
		p.Deny = append(p.Deny, m.traffic.CADir())
		p.Allow = append(p.Allow, m.traffic.CACertFiles()...)
	} else if p.DataDir != "" {
		p.Deny = append(p.Deny, filepath.Join(p.DataDir, "traffic", "_ca"))
	}
	return p
}

// browserOutputDirs returns where the browser MCP (@playwright/mcp) saves the
// screenshots, snapshots and logs it names itself: PLAYWRIGHT_MCP_OUTPUT_DIR, else
// .playwright-mcp under its working directory, which is ARTEX's (it is spawned
// without a directory and the SDK client announces no roots), or under the temp
// directory when that one is not writable. Agents read these files and
// ask_operator attaches the screenshots. Each one must pass the policy's trust
// check (agent.SetFileToolPolicy) to be used.
func browserOutputDirs() []string {
	var out []string
	if d := strings.TrimSpace(os.Getenv("PLAYWRIGHT_MCP_OUTPUT_DIR")); d != "" {
		out = append(out, absPath(d))
	}
	if wd := workingDir(); wd != "" {
		out = append(out, filepath.Join(wd, ".playwright-mcp"))
	}
	return append(out, filepath.Join(os.TempDir(), ".playwright-mcp"))
}

// workingDir is ARTEX's working directory: the browser MCP's workspace root,
// where a screenshot saved under an explicit relative filename lands.
func workingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// resolvePath returns p absolute with its links resolved, or absolute as given
// when it cannot be resolved.
func resolvePath(p string) string {
	if p == "" {
		return ""
	}
	a := absPath(p)
	if r, err := filepath.EvalSymlinks(a); err == nil {
		return r
	}
	return a
}

// pathContains reports whether path is dir or lies below it (lexically).
func pathContains(dir, path string) bool {
	if dir == "" || path == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
