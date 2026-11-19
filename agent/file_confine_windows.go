//go:build windows

package agent

import "os"

// linkCount is not available from os.FileInfo on Windows; files count as
// single-linked, so hardlinks are not detected there.
func linkCount(os.FileInfo) uint64 { return 1 }

// fileOwner is not available from os.FileInfo on Windows.
func fileOwner(os.FileInfo) (int, bool) { return 0, false }
