//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// linkCount returns the number of hard links of a file.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 1
}

// fileOwner returns the user id owning a file.
func fileOwner(fi os.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}
