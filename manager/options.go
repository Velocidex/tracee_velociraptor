package manager

import "github.com/Velocidex/tracee_velociraptor/userspace/events"

type EBPFWatchOptions struct {
	SelectedEvents []events.ID
	Prefilter      func(in []byte) bool

	Policy string
}

func NewEBPFWatchOptions() *EBPFWatchOptions {
	return &EBPFWatchOptions{}
}
