package docker

import (
	"context"
	"time"

	"github.com/moby/moby/client"
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
	du, err := CLI.DiskUsage(ctx, client.DiskUsageOptions{Containers: true, Images: true, Volumes: true, BuildCache: true})
	if err != nil {
		return nil
	}
	return &DockerInfo{
		Images:      du.Images.TotalSize,
		ImagesCount: int(du.Images.TotalCount),
		Containers:  du.Containers.TotalSize,
		Volumes:     du.Volumes.TotalSize,
		BuildCache:  du.BuildCache.TotalSize,
	}
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}
