package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Autumn-27/artex/cvematch"
	"github.com/Autumn-27/artex/cvematch/nvdsync"
)

// runCVECommand serves the one-shot CVE feed commands (-cve-sync, -cve-check):
// it works on ARTEX_CVE_FEED_DIR without starting the server or opening the
// database, and returns the process exit code.
func runCVECommand(syncFeed, full, check bool, out io.Writer) int {
	dir := strings.TrimSpace(os.Getenv("ARTEX_CVE_FEED_DIR"))
	if dir == "" {
		fmt.Fprintln(os.Stderr, "ARTEX_CVE_FEED_DIR is not set: point it at the directory that holds (or will hold) the NVD feed")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	if syncFeed {
		st, err := nvdsync.Sync(ctx, nvdsync.Options{
			Dir: dir, APIKey: strings.TrimSpace(os.Getenv("ARTEX_NVD_API_KEY")), Full: full, Logf: log.Printf,
		})
		if err != nil {
			log.Printf("[cve-sync] %v", err)
			return 1
		}
		_ = enc.Encode(map[string]any{"sync": st})
	}
	src, err := cvematch.LoadNVDDir(dir)
	if err != nil {
		log.Printf("[cve] %v", err)
		return 1
	}
	st := src.Stats()
	_ = enc.Encode(map[string]any{"feed": st})
	if syncFeed {
		fmt.Fprintln(out, "A running ARTEX server picks the new feed up on POST /api/settings/cve/reload or a restart.")
	}
	if check && st.CVEs == 0 {
		return 1
	}
	return 0
}
