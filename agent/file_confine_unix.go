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
