package derive

import (
	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/events/parse"
	"github.com/Velocidex/tracee_velociraptor/userspace/types/trace"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils/environment"
)

// Struct names for the interfaces HookedSeqOpsEventID checks for hooks
// The show,start,next and stop operation function pointers will be checked for each of those
var NetSeqOps = [6]string{
	"tcp4_seq_ops",
	"tcp6_seq_ops",
	"udp_seq_ops",
	"udp6_seq_ops",
	"raw_seq_ops",
	"raw6_seq_ops",
}

var NetSeqOpsFuncs = [4]string{
	"show",
	"start",
	"next",
	"stop",
}

func HookedSeqOps(kernelSymbols *environment.KernelSymbolTable) DeriveFunction {
	return deriveSingleEvent(events.HookedSeqOps, deriveHookedSeqOpsArgs(kernelSymbols))
}

func deriveHookedSeqOpsArgs(kernelSymbols *environment.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		seqOpsArr, err := parse.ArgVal[[]uint64](event.Args, "net_seq_ops")
		if err != nil || len(seqOpsArr) < 1 {
			return nil, errfmt.WrapError(err)
		}
		hookedSeqOps := make(map[string]trace.HookedSymbolData, 0)
		for i, addr := range seqOpsArr {
			// text segment check is done in kernel, marked as 0
			if addr == 0 {
				continue
			}
			hookingFunction := utils.ParseSymbol(addr, kernelSymbols)
			seqOpsStruct := NetSeqOps[i/4]
			seqOpsFunc := NetSeqOpsFuncs[i%4]
			hookedSeqOps[seqOpsStruct+"_"+seqOpsFunc] =
				trace.HookedSymbolData{SymbolName: hookingFunction.Name, ModuleOwner: hookingFunction.Owner}
		}
		return []interface{}{hookedSeqOps}, nil
	}
}
