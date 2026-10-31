package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"

	"dockpilot/internal/config"
)

type ContainerInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Image   string   `json:"image"`
	State   string   `json:"state"`
	Running bool     `json:"running"`
	Status  string   `json:"status"`
	Stack   string   `json:"stack"`
	CPU     *float64 `json:"cpu"`
	Mem     *float64 `json:"mem"`
	MemUsed *int64   `json:"mem_used"`
	MemLim  *int64   `json:"mem_limit"`
	NetRx   *uint64  `json:"net_rx"`
	NetTx   *uint64  `json:"net_tx"`
}

func ListContainers(ctx context.Context) ([]ContainerInfo, error) {
	cs, err := CLI.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	var totalMem uint64
	if info, err := CLI.Info(ctx); err == nil {
		totalMem = uint64(info.MemTotal)
	}
	results := make([]ContainerInfo, len(cs))
	var wg sync.WaitGroup
	for i, c := range cs {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		results[i] = ContainerInfo{
			ID:      c.ID[:12],
			Name:    name,
			Image:   c.Image,
			State:   c.State,
			Running: c.State == "running",
			Status:  c.Status,
			Stack:   c.Labels["com.docker.compose.project"],
		}
		if c.State == "running" {
			wg.Add(1)
			go func(idx int, cid string) {
				defer wg.Done()
				fillStats(ctx, cid, &results[idx], totalMem)
			}(i, c.ID)
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].Running != results[j].Running {
			return results[i].Running
		}
		return results[i].Name < results[j].Name
	})
	return results, nil
}

func fillStats(ctx context.Context, id string, info *ContainerInfo, totalMem uint64) {
	resp, err := CLI.ContainerStats(ctx, id, false)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var s container.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return
	}

	// CPU
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	ncpu := float64(s.CPUStats.OnlineCPUs)
	if ncpu == 0 {
		ncpu = float64(len(s.CPUStats.CPUUsage.PercpuUsage))
		if ncpu == 0 {
			ncpu = 1
		}
	}
	if sysDelta > 0 && cpuDelta >= 0 {
		v := math.Round((cpuDelta/sysDelta)*ncpu*10000) / 100
		info.CPU = &v
	}

	// Memory: cgroupv2 unlimited containers report max_uint64 as limit,
	// which overflows int64. Fall back to host total memory (same as `docker stats`).
	lim := s.MemoryStats.Limit
	if lim == 0 || lim > math.MaxInt64 {
		lim = totalMem
	}
	if lim > 0 {
		// cgroupv2 uses "inactive_file" instead of "cache"
		cache := s.MemoryStats.Stats["cache"]
		if cache == 0 {
			cache = s.MemoryStats.Stats["inactive_file"]
		}
		used := int64(s.MemoryStats.Usage) - int64(cache)
		if used < 0 {
			used = int64(s.MemoryStats.Usage)
		}
		limI := int64(lim)
		info.MemUsed = &used
		info.MemLim = &limI
		pct := math.Round(float64(used)/float64(limI)*10000) / 100
		info.Mem = &pct
	}

	var rx, tx uint64
	for _, n := range s.Networks {
		rx += n.RxBytes
		tx += n.TxBytes
	}
	info.NetRx = &rx
	info.NetTx = &tx
}

func ContainerAction(ctx context.Context, id, action string) error {
	switch action {
	case "start":
		return CLI.ContainerStart(ctx, id, container.StartOptions{})
	case "stop":
		return CLI.ContainerStop(ctx, id, container.StopOptions{})
	case "restart":
		return CLI.ContainerRestart(ctx, id, container.StopOptions{})
	case "update":
		return recreateWithNewImage(ctx, id)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func recreateWithNewImage(ctx context.Context, id string) error {
	c, err := CLI.ContainerInspect(ctx, id)
	if err != nil {
		return err
	}
	imageRef := c.Config.Image

	pullAuth := config.PullAuthForImage(imageRef)
	out, err := CLI.ImagePull(ctx, imageRef, image.PullOptions{RegistryAuth: pullAuth})
	if err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}
	io.Copy(io.Discard, out)
	out.Close()

	var primaryNet string
	var primaryEP *network.EndpointSettings
	for netName, ep := range c.NetworkSettings.Networks {
		primaryNet = netName
		primaryEP = ep
		break
	}
	netCfg := &network.NetworkingConfig{}
	if primaryNet != "" {
		netCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			primaryNet: {Aliases: filterAliases(primaryEP.Aliases, c.ID[:12])},
		}
	}

	if err := CLI.ContainerStop(ctx, c.ID, container.StopOptions{}); err != nil {
		return fmt.Errorf("stop failed: %w", err)
	}
	if err := CLI.ContainerRemove(ctx, c.ID, container.RemoveOptions{}); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}

	resp, err := CLI.ContainerCreate(ctx, c.Config, c.HostConfig, netCfg, nil, c.Name)
	if err != nil {
		return fmt.Errorf("create failed: %w", err)
	}

	for netName, ep := range c.NetworkSettings.Networks {
		if netName == primaryNet {
			continue
		}
		CLI.NetworkConnect(ctx, netName, resp.ID, &network.EndpointSettings{
			Aliases: filterAliases(ep.Aliases, c.ID[:12]),
		})
	}
	return CLI.ContainerStart(ctx, resp.ID, container.StartOptions{})
}

func filterAliases(aliases []string, shortID string) []string {
	result := make([]string, 0)
	for _, a := range aliases {
		if a != shortID {
			result = append(result, a)
		}
	}
	return result
}

func ContainerSizes(ctx context.Context) (map[string]struct{ RW, RootFS int64 }, error) {
	result := map[string]struct{ RW, RootFS int64 }{}
	cs, err := CLI.ContainerList(ctx, container.ListOptions{All: true, Size: true})
	if err != nil {
		return result, err
	}
	for _, c := range cs {
		result[c.ID[:12]] = struct{ RW, RootFS int64 }{c.SizeRw, c.SizeRootFs}
	}
	return result, nil
}

func SelfContainerID() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		for _, seg := range strings.Split(parts[2], "/") {
			seg = strings.TrimPrefix(seg, "docker-")
			seg = strings.TrimSuffix(seg, ".scope")
			if len(seg) == 64 {
				return seg[:12]
			}
		}
	}
	return ""
}
