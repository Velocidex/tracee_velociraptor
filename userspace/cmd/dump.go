package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Velocidex/tracee_velociraptor/manager"
	"github.com/Velocidex/tracee_velociraptor/userspace/cmd/flags"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/policy/v1beta1"
	"github.com/alecthomas/kingpin"
)

var (
	dump_command        = app.Command("dump", "Dump eBPF events.")
	dump_command_events = dump_command.Arg(
		"events", "One or more events to show").Strings()

	dump_command_sets = dump_command.Flag("sets", "Specify events as sets").Bool()

	dump_command_policy = dump_command.Flag("policy", "Policy to load").Strings()
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

	config := manager.Config{
		Options: manager.OptTranslateFDFilePath | manager.OptExecEnv,

		// This does not matter here because the program exits as soon
		// as the provider is idle, but in a long living program this
		// controls when to unload the ebpf program.
		IdleUnloadTimeout: 5 * time.Second,
	}

	mgr, err := manager.NewEBPFManager(ctx, config, logger)
	if err != nil {
		kingpin.FatalIfError(err, "NewEBPFManager")
	}
	defer mgr.Close()

	opts := manager.EBPFWatchOptions{
		SelectedEvents: selected_events,
	}

	if len(*dump_command_policy) > 0 {
		policies, err := v1beta1.PoliciesFromPaths(*dump_command_policy)
		kingpin.FatalIfError(err, "NewEBPFManager")

		fmt.Printf("Policies %#v\n", policies)

		scope_map, event_map, err := flags.PrepareFilterMapsFromPolicies(policies)
		kingpin.FatalIfError(err, "PrepareFilterMapsFromPolicies")
		ps, err := flags.CreatePolicies(scope_map, event_map)
		kingpin.FatalIfError(err, "CreatePolicies")

		fmt.Printf("Policies %#v\n", ps)

		return
	}

	output_chan, closer, err := mgr.Watch(ctx, opts)
	if err != nil {
		logger.Error("Watch: %v", err)
		return
	}
	defer closer()

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
