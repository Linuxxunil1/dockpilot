//go:build linux

package docker

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var prevCPUIdle, prevCPUTotal uint64

func cpuPercent() float64 {
	idle, total := readCPUStat()
	if prevCPUTotal == 0 {
		prevCPUIdle, prevCPUTotal = idle, total
		time.Sleep(200 * time.Millisecond)
		idle, total = readCPUStat()
	}
	td := total - prevCPUTotal
	id := idle - prevCPUIdle
	prevCPUIdle, prevCPUTotal = idle, total
	if td == 0 {
		return 0
	}
	return round2((1.0 - float64(id)/float64(td)) * 100)
}

func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		for i, v := range strings.Fields(line)[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle + iowait
				idle += n
			}
		}
		return
	}
	return
}

func memStats() (total, used uint64, pct float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	m := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) >= 2 {
			v, _ := strconv.ParseUint(parts[1], 10, 64)
			m[strings.TrimSuffix(parts[0], ":")] = v * 1024
		}
	}
	total = m["MemTotal"]
	avail := m["MemAvailable"]
	if avail == 0 {
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	if total > avail {
		used = total - avail
	}
	if total > 0 {
		pct = round2(float64(used) / float64(total) * 100)
	}
	return
}

func diskStats(path string) (total, used uint64, pct float64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	if total > free {
		used = total - free
	}
	if total > 0 {
		pct = round2(float64(used) / float64(total) * 100)
	}
	return
}

func uptimeSecs() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(parts[0], 64)
	return v
}

func numCPU() int {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return runtime.NumCPU()
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "processor") {
			count++
		}
	}
	if count == 0 {
		return runtime.NumCPU()
	}
	return count
}

func loadAvg() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return nil
	}
	result := make([]float64, 3)
	for i := 0; i < 3; i++ {
		result[i], _ = strconv.ParseFloat(parts[i], 64)
	}
	return result
}
