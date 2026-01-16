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

func DisplayBPS(bytes uint64, duration time.Duration) string {
	if duration <= 0 {
		return "0 bps"
	}
	bps := float64(bytes) / duration.Seconds() * 8

	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f GBPS", bps/gb)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f MBPS", bps/mb)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f KBPS", bps/kb)
	default:
		return fmt.Sprintf("%.2f BPS", bps)
	}
}

func DisplayBiPS(bytes uint64, duration time.Duration) string {
	if duration <= 0 {
		return "0 bps"
	}
	bps := float64(bytes) / duration.Seconds() * 8

	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.2f GiBPS", bps/gib)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f MiBPS", bps/mib)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f KiBPS", bps/kib)
	default:
		return fmt.Sprintf("%.2f BPS", bps)
	}
}

func DisplayB(bytes uint64) string {
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

func DisplayBi(bytes uint64) string {
	switch {
	case bytes >= gib:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/gib)
	case bytes >= mib:
		return fmt.Sprintf("%.2f MiB", float64(bytes)/mib)
	case bytes >= kib:
		return fmt.Sprintf("%.2f KiB", float64(bytes)/kib)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
