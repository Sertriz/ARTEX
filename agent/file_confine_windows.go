//go:build windows

package agent

import "os"

// linkCount is not available from os.FileInfo on Windows; files count as single-linked.
func linkCount(os.FileInfo) uint64 { return 1 }
