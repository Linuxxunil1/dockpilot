package docker

import (
	"context"
	"time"

	dtypes "github.com/docker/docker/api/types"
)

type DiskInfo struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
	Free  uint64 `json:"free"`
}

type DockerInfo struct {
	Images      int64 `json:"images"`
	ImagesCount int   `json:"images_count"`
	Containers  int64 `json:"containers"`
	Volumes     int64 `json:"volumes"`
	BuildCache  int64 `json:"build_cache"`
}

type HostStats struct {
	CPU      *float64    `json:"cpu"`
	CPUs     int         `json:"cpus"`
	Load     []float64   `json:"load,omitempty"`
	MemPct   *float64    `json:"mem_pct"`
	MemUsed  uint64      `json:"mem_used"`
	MemTotal uint64      `json:"mem_total"`
	Disk     *DiskInfo   `json:"disk,omitempty"`
	Docker   *DockerInfo `json:"docker,omitempty"`
	Uptime   float64     `json:"uptime"`
}

func GetHostStats() HostStats {
	s := HostStats{}

	cpu := cpuPercent()
	s.CPU = &cpu
	s.CPUs = numCPU()
	s.Load = loadAvg()

	s.MemTotal, s.MemUsed, _ = memStats()
	if s.MemTotal > 0 {
		pct := round2(float64(s.MemUsed) / float64(s.MemTotal) * 100)
		s.MemPct = &pct
	}

	total, used, _ := diskStats("/")
	if total > 0 {
		free := uint64(0)
		if total > used {
			free = total - used
		}
		s.Disk = &DiskInfo{Total: total, Used: used, Free: free}
	}

	s.Uptime = uptimeSecs()
	s.Docker = dockerDiskInfo()

	return s
}

func dockerDiskInfo() *DockerInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	du, err := CLI.DiskUsage(ctx, dtypes.DiskUsageOptions{})
	if err != nil {
		return nil
	}
	info := &DockerInfo{}
	for _, img := range du.Images {
		info.Images += img.Size
		info.ImagesCount++
	}
	for _, c := range du.Containers {
		info.Containers += c.SizeRw
	}
	for _, v := range du.Volumes {
		if v.UsageData != nil {
			info.Volumes += v.UsageData.Size
		}
	}
	for _, b := range du.BuildCache {
		if !b.Shared {
			info.BuildCache += b.Size
		}
	}
	return info
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}
