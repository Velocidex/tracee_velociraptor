package ebpf

import "time"

type Stats struct {
	NumberOfListeners int
	EIDMonitored      []map[string]int

	IdleTime          time.Duration
	IdleUnloadTimeout time.Duration

	EBFProgramStatus string

	// Total event seen before prefilter
	PrefilterEventCount int

	// Total events parsed
	EventCount int
}
