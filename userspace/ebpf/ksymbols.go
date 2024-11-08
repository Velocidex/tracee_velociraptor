package ebpf

import (
	"unsafe"

	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/logger"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils/environment"
)

// TODO: Just like recent change in `KernelSymbolTable`, in kernel_symbols.go,
// this needs to be changed somehow. Symbols might be duplicated, so might be
// the addresses (https://github.com/aquasecurity/tracee/issues/3798).

var maxKsymNameLen = 64 // Most match the constant in the bpf code
var globalSymbolOwner = "system"

func (self *EBPFManager) UpdateKallsyms() error {
	// NOTE: Make sure to refresh the kernel symbols table before updating the eBPF map.

	// Find the eBPF map.
	bpfKsymsMap, err := self.bpfModule.GetMap("ksymbols_map")
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Get the symbols all events being traced require (t.eventsState already
	// includes dependent events, no need to recurse again).
	allReqSymbols := self.getRequiredKsyms()

	self.logger.Debug("Required KSyms %v\n", allReqSymbols)

	kernelSymbols, err := environment.NewKernelSymbolTable(
		environment.WithRequiredSymbols(allReqSymbols),
	)

	// For every ksymbol required by tracee ...
	for _, required := range allReqSymbols {
		// ... get the symbol address from the kallsyms file ...
		symbol, err := kernelSymbols.GetSymbolByOwnerAndName(globalSymbolOwner, required)
		if err != nil {
			logger.Debugw("failed to get symbol", "symbol", required, "error", err)
			continue
		}

		// ... and update the eBPF map with the symbol address.
		for _, sym := range symbol {
			key := make([]byte, maxKsymNameLen)
			copy(key, sym.Name)
			addr := sym.Address

			// Update the eBPF map with the symbol address.
			err := bpfKsymsMap.Update(
				unsafe.Pointer(&key[0]),
				unsafe.Pointer(&addr),
			)
			if err != nil {
				return errfmt.WrapError(err)
			}
		} // will overwrite the previous value (check TODO)
	}

	return nil
}
