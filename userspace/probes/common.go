package probes

import (
	bpf "github.com/Velocidex/tracee_velociraptor/userspace/compat/bpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
)

// enableDisableAutoload enables or disables an eBPF program automatic attachment to/from its hook.
func enableDisableAutoload(module *bpf.Module, programName string, autoload bool) error {
	var err error

	if module == nil || programName == "" {
		return errfmt.Errorf("incorrect arguments (program: %s)", programName)
	}

	prog, err := module.GetProgram(programName)
	if err != nil {
		return errfmt.WrapError(err)
	}

	return prog.SetAutoload(autoload)
}
