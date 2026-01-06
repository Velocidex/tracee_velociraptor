package manager

import (
	"unsafe"

	"github.com/Velocidex/tracee_velociraptor/userspace/ebpf/initialization"
	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

func (self *EBPFManager) populateBPFMaps() error {
	// Prepare 32bit to 64bit syscall number mapping
	sys32to64BPFMap, pres := self.collection.Maps["sys_32_to_64_map"] // u32, u32
	if !pres {
		return mapNotValid
	}
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id32BitU32 := uint32(eventDefinition.GetID32Bit()) // ID32Bit is int32
		idU32 := uint32(eventDefinition.GetID())           // ID is int32
		err := sys32to64BPFMap.Put(unsafe.Pointer(&id32BitU32), unsafe.Pointer(&idU32))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	// Update the kallsyms eBPF map with all symbols from the kallsyms file.
	err := self.UpdateKallsyms()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize kconfig ebpf map with values from the kernel config file.
	// TODO: remove this from libbpf and try to rely in libbpf only for kconfig vars.
	bpfKConfigMap, err := self.bpfModule.GetMap("kconfig_map") // u32, u32
	if err != nil {
		return errfmt.WrapError(err)
	}
	kconfigValues, err := initialization.LoadKconfigValues(self.KernelConfig)
	if err != nil {
		return errfmt.WrapError(err)
	}
	for key, value := range kconfigValues {
		keyU32 := uint32(key)
		valueU32 := uint32(value)
		err = bpfKConfigMap.Update(unsafe.Pointer(&keyU32), unsafe.Pointer(&valueU32))
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	/*
					// Initialize the net_packet configuration eBPF map.
					if pcaps.PcapsEnabled(t.config.Capture.Net) {
						bpfNetConfigMap, err := t.bpfModule.GetMap("netconfig_map")
						if err != nil {
							return errfmt.WrapError(err)
						}

						netConfigVal := make([]byte, 8) // u32 capture_options + u32 capture_length
						options := pcaps.GetPcapOptions(t.config.Capture.Net)
						binary.LittleEndian.PutUint32(netConfigVal[0:4], uint32(options))
						binary.LittleEndian.PutUint32(netConfigVal[4:8], t.config.Capture.Net.CaptureLength)

						cZero := uint32(0)
						err = bpfNetConfigMap.Update(unsafe.Pointer(&cZero), unsafe.Pointer(&netConfigVal[0]))
						if err != nil {
							return errfmt.Errorf("error updating net config eBPF map: %v", err)
						}
					}

					// Initialize config and filter maps
					err = t.populateFilterMaps(false)
					if err != nil {
						return errfmt.WrapError(err)
					}

				// Populate containers map with existing containers
				err = t.containers.PopulateBpfMap(t.bpfModule)
				if err != nil {
					return errfmt.WrapError(err)
				}

			// Set filters given by the user to filter file write events
			fileWritePathFilterMap, err := t.bpfModule.GetMap("file_write_path_filter") // u32, u32
			if err != nil {
				return err
			}

			for i := uint32(0); i < uint32(len(t.config.Capture.FileWrite.PathFilter)); i++ {
				filterFilePathWriteBytes := []byte(t.config.Capture.FileWrite.PathFilter[i])
				if err = fileWritePathFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&filterFilePathWriteBytes[0])); err != nil {
					return err
				}
			}

			// Set filters given by the user to filter file read events
			fileReadPathFilterMap, err := t.bpfModule.GetMap("file_read_path_filter") // u32, u32
			if err != nil {
				return err
			}

			for i := uint32(0); i < uint32(len(t.config.Capture.FileRead.PathFilter)); i++ {
				filterFilePathReadBytes := []byte(t.config.Capture.FileRead.PathFilter[i])
				if err = fileReadPathFilterMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&filterFilePathReadBytes[0])); err != nil {
					return err
				}
			}

			// Set filters given by the user to filter file read and write type and fds
			fileTypeFilterMap, err := t.bpfModule.GetMap("file_type_filter") // u32, u32
			if err != nil {
				return errfmt.WrapError(err)
			}

		// Should match the value of CAPTURE_READ_TYPE_FILTER_IDX in eBPF code
		captureReadTypeFilterIndex := uint32(0)
		captureReadTypeFilterVal := uint32(t.config.Capture.FileRead.TypeFilter)
		if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureReadTypeFilterIndex),
			unsafe.Pointer(&captureReadTypeFilterVal)); err != nil {
			return errfmt.WrapError(err)
		}

		// Should match the value of CAPTURE_WRITE_TYPE_FILTER_IDX in eBPF code
		captureWriteTypeFilterIndex := uint32(1)
		captureWriteTypeFilterVal := uint32(t.config.Capture.FileWrite.TypeFilter)
		if err = fileTypeFilterMap.Update(unsafe.Pointer(&captureWriteTypeFilterIndex),
			unsafe.Pointer(&captureWriteTypeFilterVal)); err != nil {
			return errfmt.WrapError(err)
		}

		// Initialize tail call dependencies
		eventsToSubmit := t.policyManager.EventsToSubmit()
		tailCalls := events.Core.GetTailCalls(eventsToSubmit)
		for _, tailCall := range tailCalls {
			err := t.initTailCall(tailCall)
			if err != nil {
				return errfmt.Errorf("failed to initialize tail call: %v", err)
			}
		}
	*/

	return nil
}
