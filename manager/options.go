package manager

import "github.com/Velocidex/tracee_velociraptor/userspace/events"

type EBPFWatchOptions struct {
	// Forward all these events to the watcher.
	SelectedEvents []events.ID
	Prefilter      func(in []byte) bool

	// Alternatively callers can supply a policy.
	//
	// The policy can provide filters and a set of events. Filters are
	// applied in the kernel so they are essential for reducing CPU
	// use.
	//
	// For example:
	//
	// metadata:
	//    name: file-open-home
	// spec:
	//   scope:
	//     - global
	//   rules:
	//     - event: security_file_open
	//       filters:
	//         - args.pathname=/home/*
	Policy string
}

func NewEBPFWatchOptions() *EBPFWatchOptions {
	return &EBPFWatchOptions{}
}
