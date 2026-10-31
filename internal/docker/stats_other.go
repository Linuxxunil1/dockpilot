//go:build !linux

package docker

import "runtime"

func cpuPercent() float64                        { return 0 }
func memStats() (uint64, uint64, float64)        { return 0, 0, 0 }
func diskStats(string) (uint64, uint64, float64) { return 0, 0, 0 }
func uptimeSecs() float64                        { return 0 }
func numCPU() int                                { return runtime.NumCPU() }
func loadAvg() []float64                         { return nil }
