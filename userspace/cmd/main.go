package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Velocidex/tracee_velociraptor/userspace/ebpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

func main() {
	manager, err := ebpf.NewEBPFManager()
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
			fmt.Printf("ebpf_process: %s", err)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Minute)
	defer cancel()

	err = manager.Watch(ctx)
	if err != nil {
		fmt.Printf("ebpf_process: %s", err)
		return
	}
}
