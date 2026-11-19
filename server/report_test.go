package server

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// The task report lists only what triage kept and counts only the task's own
// assets. The asset graph is shared by every task, so a global count would put
// the size of other engagements into this one's deliverable.
func TestGetReportTriageAndTaskAssets(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}

	own, err := m.CreateTask("report scope test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.CreateTask("report scope other", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = m.DeleteTask(own.ID, DeleteTaskOptions{})
		_, _ = m.DeleteTask(other.ID, DeleteTaskOptions{})
	}()

	stamp := time.Now().UnixNano()
	var assetIDs []int64
	defer func() { _, _ = m.Assets().DeleteByIDs(assetIDs) }()
	addDomains := func(task *Task, n int) {
		tid := mustTaskID(t, task.ID)
		for i := 0; i < n; i++ {
			id, err := m.Assets().UpsertRootDomain(db.UpsertRootDomainReq{Domain: fmt.Sprintf("report-%d-%s-%d.example", stamp, task.ID, i), TaskID: tid})
			if err != nil {
				t.Fatal(err)
			}
			assetIDs = append(assetIDs, id)
		}
	}
	addDomains(own, 2)
	addDomains(other, 3)

	var findingIDs []int64
	defer func() {
		for _, id := range findingIDs {
			_, _ = m.pg.DeleteFinding(id)
		}
	}()
	addFinding := func(name, status string) {
		nid, err := own.Store.AddNode(db.KindFinding, map[string]any{"name": name, "severity": "high", "summary": "s"}, 0, "confirmed", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err := m.pg.AddFinding(mustTaskID(t, own.ID), nid, "xss", name, "high", "s", "poc", "worker", nil)
		if err != nil {
			t.Fatal(err)
		}
		findingIDs = append(findingIDs, fid)
		if _, err := m.pg.SetFindingStatus(fid, status); err != nil {
			t.Fatal(err)
		}
	}
	addFinding("kept-confirmed", db.FindingConfirmed)
	addFinding("kept-pending", db.FindingPending)
	addFinding("kept-accepted", db.FindingRiskAccepted)
	addFinding("dropped-fp", db.FindingFalsePositive)
	addFinding("dropped-dup", db.FindingDuplicate)
	addFinding("dropped-ignored", db.FindingIgnored)

	w := httptest.NewRecorder()
	s.getReport(w, httptest.NewRequest("GET", "/api/report?task="+own.ID, nil))
	if w.Code != 200 {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	md := w.Body.String()
	for _, want := range []string{
		"- Findings: **3** (1 confirmed, 1 pending, 1 risk accepted)",
		"- Excluded at triage: **3** (1 false positive, 1 duplicate, 1 ignored)",
		"- Assets: root_domain 2\n",
		"kept-confirmed", "kept-pending", "kept-accepted",
		"- **Status**: risk_accepted",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
	for _, gone := range []string{"dropped-fp", "dropped-dup", "dropped-ignored", "Confirmed findings"} {
		if strings.Contains(md, gone) {
			t.Errorf("report contains %q\n%s", gone, md)
		}
	}

	// The no-LLM chat summary counts the same way.
	if reply := s.fallbackChat(own, "status"); !strings.Contains(reply, "assets 2,") || !strings.Contains(reply, "findings 3.") {
		t.Errorf("fallbackChat reply = %q, want assets 2 and findings 3", reply)
	}
}

// A read that fails must fail the report, not render it as "no findings". The
// task lives only in memory, so closing the pool leaves no rows behind.
func TestGetReportFailsOnReadError(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	s := &Server{m: m}
	const id = "report-read-failure"
	m.mu.Lock()
	m.tasks[id] = &Task{ID: id, Store: m.pg.Exploration(0)}
	m.mu.Unlock()
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.getReport(w, httptest.NewRequest("GET", "/api/report?task="+id, nil))
	// The body names the failing read: the later quality lookup would also answer 500
	// on a closed pool and hide a regression of this check.
	if w.Code != 500 || !strings.Contains(w.Body.String(), "findings lookup failed") {
		t.Fatalf("report on a failed read: %d %s", w.Code, w.Body)
	}
}
