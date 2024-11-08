package ebpf

import "time"

type Stats struct {
	NumberOfListeners int
	EIDMonitored      []map[string]int

	IdleTime          time.Duration
	IdleUnloadTimeout time.Duration

	EBFProgramStatus string

	EventCount int
}
