package main

import (
	"encoding/json"
	"fmt"

	"github.com/Velocidex/tracee_velociraptor/userspace/ebpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

func main() {
	ctx, cancel := InstallSignalHandler()
	defer cancel()

	logger := NewLogger()

	manager, err := ebpf.NewEBPFManager(logger)
	if err != nil {
		fmt.Printf("ebpf_process: %s", err)
		return
	}

	defer manager.Close()

	for _, eid := range []events.ID{
		events.SecuritySocketListen,
		events.SchedProcessExec,
		events.HiddenKernelModuleSeeker,
	} {
		err = manager.InstallEventIDPolicy(eid)
		if err != nil {
			logger.Error("InstallEventIDPolicy: %v", err)
			return
		}
	}

	output_chan, err := manager.Watch(ctx)
	if err != nil {
		logger.Error("Watch: %v", err)
		return
	}

	for row := range output_chan {
		serialized, err := json.Marshal(row)
		if err != nil {
			continue
		}

		fmt.Println(string(serialized))
	}
}
