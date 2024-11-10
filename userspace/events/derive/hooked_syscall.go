package derive

import (
	"fmt"

	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/events/parse"
	"github.com/Velocidex/tracee_velociraptor/userspace/types/trace"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils/environment"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	maxSysCallTableSize = 500
)

var (
	reportedHookedSyscalls *lru.Cache[int32, uint64]
)

// InitHookedSyscall initialize lru
func InitHookedSyscall() error {
	var err error
	reportedHookedSyscalls, err = lru.New[int32, uint64](maxSysCallTableSize)
	return err
}

func DetectHookedSyscall(kernelSymbols *environment.KernelSymbolTable) DeriveFunction {
	return deriveSingleEvent(events.HookedSyscall, deriveDetectHookedSyscallArgs(kernelSymbols))
}

func deriveDetectHookedSyscallArgs(kernelSymbols *environment.KernelSymbolTable) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		syscallId, err := parse.ArgVal[int32](event.Args, "syscall_id")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_id arg: %v", err)
		}

		address, err := parse.ArgVal[uint64](event.Args, "syscall_address")
		if err != nil {
			return nil, errfmt.Errorf("error parsing syscall_address arg: %v", err)
		}

		alreadyReportedAddress, found := reportedHookedSyscalls.Get(syscallId)
		if found && alreadyReportedAddress == address {
			return nil, nil
		}

		reportedHookedSyscalls.Add(syscallId, address) // Upsert

		hookedFuncName := ""
		hookedOwner := ""
		hookedFuncSymbol, err := kernelSymbols.GetSymbolByAddr(address)
		if err == nil {
			hookedFuncName = hookedFuncSymbol[0].Name
			hookedOwner = hookedFuncSymbol[0].Owner
		}

		syscallName := convertToSyscallName(syscallId)
		hexAddress := fmt.Sprintf("%x", address)

		return []interface{}{syscallName, hexAddress, hookedFuncName, hookedOwner}, nil
	}
}

func convertToSyscallName(syscallId int32) string {
	definition, ok := events.CoreEvents[events.ID(syscallId)]
	if !ok {
		return ""
	}
	return definition.GetName()
}
