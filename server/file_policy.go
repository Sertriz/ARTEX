package server

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/agent"
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
//   - the key directory itself, unless it also holds the data or the skills
//     (on bare metal it defaults to the install directory, which does);
//   - the proxy CA store, whose private key signs certificates every client of
//     the proxy trusts. Its certificate files stay readable (Allow).
func fileToolPolicyFor(m *Manager, skillDir, dataDir, keyDir string) agent.FileToolPolicy {
	p := agent.FileToolPolicy{DataDir: absPath(dataDir), SkillsDir: absPath(skillDir), ReadDirs: browserOutputDirs()}
	if keyDir != "" {
		kd := absPath(keyDir)
		p.Deny = append(p.Deny, filepath.Join(kd, jwtKeyFilename), filepath.Join(kd, db.SecretKeyFile))
		if !pathContains(kd, p.DataDir) && !pathContains(kd, p.SkillsDir) {
			p.Deny = append(p.Deny, kd)
		}
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
// ask_operator attaches the screenshots.
func browserOutputDirs() []string {
	var out []string
	if d := strings.TrimSpace(os.Getenv("PLAYWRIGHT_MCP_OUTPUT_DIR")); d != "" {
		out = append(out, absPath(d))
	}
	if wd, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(wd, ".playwright-mcp"))
	}
	return append(out, filepath.Join(os.TempDir(), ".playwright-mcp"))
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

// pathContains reports whether path is dir or lies below it (lexically).
func pathContains(dir, path string) bool {
	if dir == "" || path == "" {
		return false
	}
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
