package main

import (
	"encoding/json"
	"fmt"

	"github.com/Velocidex/tracee_velociraptor/userspace/ebpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/alecthomas/kingpin"
)

var (
	dump_command        = app.Command("dump", "Dump eBPF events.")
	dump_command_events = dump_command.Arg(
		"events", "One or more events to show").Strings()

	dump_command_sets = dump_command.Flag("sets", "Specify events as sets").Bool()
)

func doDump() {
	ctx, cancel := InstallSignalHandler()
	defer cancel()

	logger := NewLogger()

	var selected_events []events.ID

	if *dump_command_sets {
		sets := getEventsBySets()
		for _, set_name := range *dump_command_events {
			event_names, pres := sets[set_name]
			if !pres {
				logger.Error("Unknown set name %v", set_name)
				continue
			}

			for _, event_name := range event_names {
				id, err := getEventId(event_name)
				if err != nil {
					logger.Error("%v", err)
					continue
				}
				selected_events = append(selected_events, id)
			}
		}

	} else {
		for _, event_name := range *dump_command_events {
			id, err := getEventId(event_name)
			if err != nil {
				logger.Error("%v", err)
				continue
			}
			selected_events = append(selected_events, id)
		}
	}

	manager, err := ebpf.NewEBPFManager(ctx, logger)
	if err != nil {
		kingpin.FatalIfError(err, "NewEBPFManager")
	}

	defer manager.Close()

	for _, eid := range selected_events {
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

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case dump_command.FullCommand():
			doDump()
		default:
			return false
		}
		return true
	})
}
