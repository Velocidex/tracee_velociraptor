package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Velocidex/tracee_velociraptor/manager"
	"github.com/alecthomas/kingpin"
)

var (
	dump_command        = app.Command("dump", "Dump eBPF events.")
	dump_command_events = dump_command.Arg(
		"events", "One or more events to show").Strings()

	dump_command_sets = dump_command.Flag("sets", "Specify events as sets").Bool()

	dump_command_policy = dump_command.Flag("policy", "Policy to load").String()
)

func doDump() {
	ctx, cancel := InstallSignalHandler()
	defer cancel()

	logger := NewLogger()

	var selected_events []string

	if *dump_command_sets {
		sets := getEventsBySets()
		for _, set_name := range *dump_command_events {
			event_names, pres := sets[set_name]
			if !pres {
				logger.Error("Unknown set name %v", set_name)
				continue
			}

			for _, event_name := range event_names {
				selected_events = append(selected_events, event_name)
			}
		}

	} else {
		selected_events = *dump_command_events
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

	var policy string
	policy, err = getPolicy()
	kingpin.FatalIfError(err, "getPolicy")

	if policy == "" {
		policy = generateDefaultPolicy(selected_events)
	}

	opts := manager.EBPFWatchOptions{
		Policy: policy,
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

func getPolicy() (string, error) {
	if *dump_command_policy == "" {
		return "", nil
	}

	fd, err := os.Open(*dump_command_policy)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	data, err := ioutil.ReadAll(fd)
	return string(data), err
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
