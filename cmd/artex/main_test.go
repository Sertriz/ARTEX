package main

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

// The shutdown cause must survive the parent context being cancelled first;
// losing it would drop the diagnostic on every graceful stop.
func TestShutdownContextPreservesNamedCause(t *testing.T) {
	signalCtx, signalCancel := context.WithCancel(context.Background())
	ctx, shutdown := shutdownContext(signalCtx)
	defer shutdown(nil)
	signalCancel()
	<-ctx.Done()
	if code, _, _, ok := agent.AbortReason(ctx); !ok || code != "shutdown" {
		t.Fatalf("code=%q ok=%v, want shutdown", code, ok)
	}
}

// -cve-sync-full alone must run the CVE command, never fall through to starting
// a second server next to the running one.
func TestCVESyncFullAloneRunsTheCommand(t *testing.T) {
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	flag.CommandLine = flag.NewFlagSet("artex", flag.ContinueOnError)
	os.Args = []string{"artex", "-cve-sync-full"}
	t.Setenv("ARTEX_CVE_FEED_DIR", "") // no feed: the command exits 2 at once
	if code := run(); code != 2 {
		t.Fatalf("run() = %d, want 2 from the CVE command", code)
	}
}
