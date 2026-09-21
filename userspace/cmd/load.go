package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/Velocidex/tracee_velociraptor/manager"
	"github.com/alecthomas/kingpin"
)

var (
	load_command = app.Command("load", "Load the ebpf engine and quit.")
)

func doLoad() {
	ctx, cancel := InstallSignalHandler()
	defer cancel()

	logger := NewLogger()

	config := manager.Config{
		Options: manager.OptTranslateFDFilePath | manager.OptExecEnv,

		// This does not matter here because the program exits as soon
		// as the provider is idle, but in a long living program this
		// controls when to unload the ebpf program.
		IdleUnloadTimeout: 5 * time.Second,
	}

	mgr, err := manager.NewEBPFManager(ctx, config, logger)
	kingpin.FatalIfError(err, "NewEBPFManager")

	defer mgr.Close()

	opts := manager.EBPFWatchOptions{
		Policy: generateDefaultPolicy([]string{
			"sched_process_exec",
		}),
	}

	fmt.Printf("Loading ....\n")
	_, closer, err := mgr.Watch(ctx, opts)
	kingpin.FatalIfError(err, "NewEBPFManager")

	defer closer()
}

func generateDefaultPolicy(events []string) string {
	var rules []string
	for _, e := range events {
		rules = append(rules, "   - event: "+e)
	}

	return fmt.Sprintf(`
metadata:
   name: policy_%d
spec:
   scope:
     - global
   rules:
`, time.Now().UnixNano()) + strings.Join(rules, "\n")
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case load_command.FullCommand():
			doLoad()
		default:
			return false
		}
		return true
	})
}
