package ebpf

import "github.com/Velocidex/tracee_velociraptor/userspace/events"

type EBPFWatchOptions struct {
	SelectedEvents []events.ID
	Prefilter      func(in []byte) bool
}
