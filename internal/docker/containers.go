package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

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

// ErrSelf: DockPilot darf sich nicht selbst stoppen, ersetzen oder eine Shell in sich öffnen.
// Im eigenen Container liegen Docker-Socket, Signaturschlüssel und alle Zugangsdaten.
var ErrSelf = errors.New("Für den DockPilot-Container selbst nicht erlaubt")

func ContainerAction(ctx context.Context, id, action string) error {
	if (action == "stop" || action == "update") && IsSelf(ctx, id) {
		return ErrSelf
	}
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
	err = pullStreamError(out)
	out.Close()
	if err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}

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

	// Der alte Container wird erst gelöscht, wenn der neue läuft. Bis dahin heißt er
	// <name>-dockpilot-old und kommt bei einem Fehler unter altem Namen zurück.
	name := strings.TrimPrefix(c.Name, "/")
	backup := name + "-dockpilot-old"
	wasRunning := c.State != nil && c.State.Running
	if err := CLI.ContainerStop(ctx, c.ID, container.StopOptions{}); err != nil {
		return fmt.Errorf("stop failed: %w", err)
	}
	if err := CLI.ContainerRename(ctx, c.ID, backup); err != nil {
		if wasRunning {
			CLI.ContainerStart(ctx, c.ID, container.StartOptions{})
		}
		return fmt.Errorf("rename failed: %w", err)
	}
	rollback := func(cause error) error {
		if err := CLI.ContainerRename(ctx, c.ID, name); err != nil {
			return fmt.Errorf("%w; Wiederherstellen fehlgeschlagen, alter Container heißt jetzt %s: %v", cause, backup, err)
		}
		if wasRunning {
			CLI.ContainerStart(ctx, c.ID, container.StartOptions{})
		}
		return fmt.Errorf("%w (alter Container wiederhergestellt)", cause)
	}

	resp, err := CLI.ContainerCreate(ctx, c.Config, c.HostConfig, netCfg, nil, name)
	if err != nil {
		return rollback(fmt.Errorf("create failed: %w", err))
	}

	for netName, ep := range c.NetworkSettings.Networks {
		if netName == primaryNet {
			continue
		}
		CLI.NetworkConnect(ctx, netName, resp.ID, &network.EndpointSettings{
			Aliases: filterAliases(ep.Aliases, c.ID[:12]),
		})
	}
	if err := CLI.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		CLI.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return rollback(fmt.Errorf("start failed: %w", err))
	}
	if err := CLI.ContainerRemove(ctx, c.ID, container.RemoveOptions{}); err != nil {
		return fmt.Errorf("neuer Container läuft, alter (%s) konnte nicht entfernt werden: %w", backup, err)
	}
	return nil
}

// pullStreamError liest den Fortschritts-Stream von ImagePull zu Ende. Fehler stehen
// dort nur im Stream (z. B. "manifest unknown"), nicht im Rückgabewert von ImagePull.
func pullStreamError(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var m struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if m.Error != "" {
			return errors.New(m.Error)
		}
	}
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

var (
	selfMu     sync.Mutex
	selfID     string // volle ID des eigenen Containers, leer solange unbekannt
	selfWarned bool
)

var mountinfoIDRe = regexp.MustCompile(`/(?:containers|overlay-containers)/([0-9a-f]{64})/`)

// selfFullID ermittelt den eigenen Container über DOCKPILOT_CONTAINER, cgroup (v1),
// mountinfo (v2, auch Podman) oder den Hostnamen. Nur ein Treffer wird gemerkt; schlägt
// die Suche fehl (z. B. Daemon kurz weg), wird beim nächsten Aufruf neu gesucht,
// damit sich der Selbstschutz nicht still abschaltet.
func selfFullID() string {
	selfMu.Lock()
	defer selfMu.Unlock()
	if selfID != "" {
		return selfID
	}
	ref := os.Getenv("DOCKPILOT_CONTAINER")
	if ref == "" {
		ref = SelfContainerID()
	}
	if ref == "" {
		if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
			if m := mountinfoIDRe.FindSubmatch(data); m != nil {
				ref = string(m[1])
			}
		}
	}
	host, _ := os.Hostname()
	if ref == "" {
		ref = host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	if ref != "" {
		var c container.InspectResponse
		c, err = CLI.ContainerInspect(ctx, ref)
		if err == nil && (ref != host || c.Config == nil || c.Config.Hostname == host) {
			selfID = c.ID
			return selfID
		}
	}
	if !selfWarned {
		selfWarned = true
		log.Printf("Selbstschutz: eigener Container nicht gefunden (%v) – ggf. DOCKPILOT_CONTAINER=<name> setzen", err)
	}
	return ""
}

// IsSelf meldet, ob ref (ID, ID-Präfix oder Name) der DockPilot-Container selbst ist.
func IsSelf(ctx context.Context, ref string) bool {
	id := selfFullID()
	if id == "" {
		return false
	}
	c, err := CLI.ContainerInspect(ctx, ref)
	return err == nil && c.ID == id
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
