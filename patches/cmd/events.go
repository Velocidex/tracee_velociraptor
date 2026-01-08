package main

import (
	"encoding/json"
	"fmt"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/manager"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/alecthomas/kingpin"
)

var (
	event_command      = app.Command("events", "Dump all available event types.")
	event_command_sets = event_command.Flag("sets", "Show only sets").Bool()
)

func getEventsBySets() map[string][]string {
	sets := make(map[string][]string)
	all_events := manager.GetEvents()
	for _, event_name := range all_events.Keys() {
		desc, _ := all_events.Get(event_name)
		e, ok := desc.(*ordereddict.Dict)
		if !ok {
			continue
		}

		set_list, _ := e.GetStrings("Sets")
		for _, s := range set_list {
			existing, _ := sets[s]
			name, pres := e.GetString("Name")
			if pres {
				existing = append(existing, name)
				sets[s] = existing
			}
		}
	}
	return sets
}

func getEventId(event_name string) (events.ID, error) {
	all_events := manager.GetEvents()
	desc_any, pres := all_events.Get(event_name)
	if !pres {
		return 0, fmt.Errorf("Unknown event name %v", event_name)
	}

	desc, ok := desc_any.(*ordereddict.Dict)
	if !ok {
		return 0, fmt.Errorf("Unknown event name %v", event_name)
	}

	id, pres := desc.GetInt64("Id")
	if !pres {
		return 0, fmt.Errorf("Unknown event name %v", event_name)
	}

	return events.ID(id), nil
}

func doEvents() {
	if *event_command_sets {
		sets := getEventsBySets()

		serialized, err := json.MarshalIndent(sets, " ", " ")
		kingpin.FatalIfError(err, "doEvents")

		fmt.Println(string(serialized))
		return
	}

	serialized, err := json.MarshalIndent(manager.GetEvents(), " ", "  ")
	kingpin.FatalIfError(err, "doEvents")

	fmt.Println(string(serialized))
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case event_command.FullCommand():
			doEvents()
		default:
			return false
		}
		return true
	})
}
