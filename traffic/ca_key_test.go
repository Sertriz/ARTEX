//go:build !windows

package traffic

import (
	"os"
	"testing"
)

// The CA private key is the ARTEX user's alone, including a key an earlier
// version left world-readable; the certificate files clients load stay readable.
func TestCAKeyRestricted(t *testing.T) {
	dir := t.TempDir()
	tr, err := Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr.Close()
	checkMode := func(path string, want os.FileMode) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("%s: mode %v, want %v", path, got, want)
		}
	}
	checkMode(CAKeyPath(dir), 0o600)

	// A key from an earlier version, 0644, is tightened on the next start.
	if err := os.Chmod(CAKeyPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, err = Open(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	checkMode(CAKeyPath(dir), 0o600)
	for _, f := range tr.CACertFiles() {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o044 != 0o044 {
			t.Fatalf("%s: mode %v, the certificate must stay readable", f, fi.Mode().Perm())
		}
	}
}
