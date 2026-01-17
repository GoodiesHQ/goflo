package utils

import (
	"fmt"
	"time"
)

const (
	kb  = 1000
	mb  = 1000 * 1000
	gb  = 1000 * 1000 * 1000
	kib = 1024
	mib = 1024 * 1024
	gib = 1024 * 1024 * 1024
)

func DisplayTime(duration time.Duration) string {
	ns := duration.Nanoseconds()
	switch {
	case ns >= int64(time.Hour):
		return fmt.Sprintf("%.2f h", duration.Hours())
	case ns >= int64(time.Minute):
		return fmt.Sprintf("%.2f m", duration.Minutes())
	case ns >= int64(time.Second):
		return fmt.Sprintf("%.2f s", duration.Seconds())
	case ns >= int64(time.Millisecond):
		return fmt.Sprintf("%.2f ms", float64(ns)/1e6)
	case ns >= int64(time.Microsecond):
		return fmt.Sprintf("%.2f µs", float64(ns)/1e3)
	default:
		return fmt.Sprintf("%d ns", ns)
	}
}

func DisplayBitsPerTime(bytes uint64, duration time.Duration) string {
	if duration <= 0 {
		return "0 bps"
	}
	bps := float64(bytes) / duration.Seconds() * 8

	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/gb)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/mb)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/kb)
	default:
		return fmt.Sprintf("%.2f bps", bps)
	}
}

func DisplayBytes(bytes uint64) string {
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.2f GB", float64(bytes)/gb)
	case bytes >= mb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/mb)
	case bytes >= kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/kb)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
