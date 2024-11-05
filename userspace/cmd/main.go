package main

import (
	"os"

	"github.com/alecthomas/kingpin"
)

type CommandHandler func(command string) bool

var (
	app = kingpin.New("ebpf_tool", "A tool for dump ebpf events.")

	verbose_flag = app.Flag(
		"verbose", "Show verbose information").Bool()

	command_handlers []CommandHandler
)

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	for _, command_handler := range command_handlers {
		if command_handler(command) {
			break
		}
	}
}
