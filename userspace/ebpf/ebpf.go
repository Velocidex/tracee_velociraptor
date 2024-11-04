package ebpf

import (
	"context"
	"errors"
	"os"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/compat/bpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/probes"
	time_util "github.com/Velocidex/tracee_velociraptor/userspace/time"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils/environment"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	tailCallsRemove = true
	tailCallsAdd    = false
)

var (
	eidNotValid = errors.New("EID Not valid")
	mapNotValid = errors.New("mapNotValie")
)

type EBPFManager struct {
	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection

	policy_id uint16

	eid_monitored map[events.ID]bool

	probes *probes.ProbeGroup

	bpfModule *bpf.Module

	kernelSymbols *environment.KernelSymbolTable

	logger Logger
}

func (self *EBPFManager) getRequiredKsyms() (res []string) {
	tmp := make(map[string]bool)
	for eid := range self.eid_monitored {
		definition, pres := events.CoreEvents[eid]
		if !pres {
			continue
		}

		for _, s := range definition.GetDependencies().GetKSymbols() {
			if s.IsRequired() {
				tmp[s.GetSymbolName()] = true
			}
		}
	}

	for k := range tmp {
		res = append(res, k)
	}

	self.logger.Debug("Required KSyms %v\n", res)
	return res
}

func (self *EBPFManager) getProbeHandles() (res []probes.Handle) {
	tmp := make(map[probes.Handle]bool)
	for eid := range self.eid_monitored {
		definition, pres := events.CoreEvents[eid]
		if !pres {
			continue
		}

		for _, p := range definition.GetDependencies().GetProbes() {
			if p.IsRequired() {
				tmp[p.GetHandle()] = true
			}
		}
	}

	for k := range tmp {
		res = append(res, k)
	}

	self.logger.Debug("Monitoring Handles %v\n", res)
	return res
}

func (self *EBPFManager) setTailCalls(eid events.ID, remove bool) error {
	definition, pres := events.CoreEvents[eid]
	if !pres {
		return eidNotValid
	}

	for _, tailCall := range definition.GetDependencies().GetTailCalls() {
		prog_array_tp_map, pres := self.collection.Maps[tailCall.GetMapName()]
		if !pres {
			continue
		}

		tail_prog, pres := self.collection.Programs[tailCall.GetProgName()]
		if !pres {
			continue
		}

		tail_prog_fd := uint32(tail_prog.FD())
		for _, idx := range tailCall.GetIndexes() {
			if remove {
				prog_array_tp_map.Delete(unsafe.Pointer(&idx))
			} else {
				prog_array_tp_map.Put(unsafe.Pointer(&idx),
					unsafe.Pointer(&tail_prog_fd))
			}
		}
	}
	return nil
}

// Installs an accept all policy for the event id
func (self *EBPFManager) InstallEventIDPolicy(eid events.ID) error {
	err := self.setTailCalls(eid, tailCallsAdd)
	if err != nil {
		return err
	}

	self.eid_monitored[eid] = true

	return self.setEventIDPolicy()
}

func (self *EBPFManager) setEventIDPolicy() error {
	event_config := &ebpfEventConfigT{
		SubmitForPolicies: uint64(self.policy_id),
	}

	var event_inner_map *ebpf.Map

	// The events_map_version is an inner map - we always renew it
	// with a new map so we can easily accound for events added and
	// removed.
	map_spec, pres := self.spec.Maps["events_map_version"]
	if !pres {
		return mapNotValid
	}

	event_inner_map, err := ebpf.NewMap(map_spec.InnerMap)
	if err != nil {
		return err
	}

	for key := range self.eid_monitored {
		eid := key
		err = event_inner_map.Put(unsafe.Pointer(&eid),
			unsafe.Pointer(event_config))
		if err != nil {
			return err
		}
	}

	event_inner_map_fd := uint32(event_inner_map.FD())
	events_map_version, pres := self.collection.Maps["events_map_version"]
	if !pres {
		return mapNotValid
	}

	return events_map_version.Put(
		unsafe.Pointer(&self.policy_id),
		unsafe.Pointer(&event_inner_map_fd))
}

func (self *EBPFManager) Close() {
	if self.collection != nil {
		self.logger.Debug("Unloading EBPF program")
		self.collection.Close()
	}
}

func (self *EBPFManager) Watch(ctx context.Context) (
	chan *ordereddict.Dict, error) {

	err := self.populateBPFMaps()
	if err != nil {
		return nil, err
	}

	kernelSymbols, err := environment.NewKernelSymbolTable(
		environment.WithRequiredSymbols(self.getRequiredKsyms()),
	)

	for _, handle := range self.getProbeHandles() {
		err := self.probes.Attach(handle, kernelSymbols)
		if err != nil {
			// Not a fatal error, keep attaching to other events.
			self.logger.Warn("Error attaching to handle %v: %v", handle, err)
			continue
		}
	}

	rd, err := perf.NewReader(self.collection.Maps["events"], 32*4096)
	if err != nil {
		return nil, err
	}

	self.logger.Debug("Reading events")

	output_chan := make(chan *ordereddict.Dict)

	go func() {
		defer self.probes.DetachAll()
		defer rd.Close()
		defer close(output_chan)

		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			event, err := decodeEvent(record.RawSample)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
				return

			case output_chan <- event:
			}
		}
	}()

	return output_chan, nil
}

func NewEBPFManager(logger Logger) (*EBPFManager, error) {
	self := &EBPFManager{
		policy_id:     1,
		eid_monitored: make(map[events.ID]bool),
		logger:        logger,
	}

	// Set the clocks and initialize.
	time_util.Init(unix.CLOCK_BOOTTIME)

	// Allow the current process to lock memory for eBPF resources.
	err := rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	start := time.Now()
	logger.Debug("Loading EBPF program into kernel")
	self.spec, err = loadEbpf()
	if err != nil {
		return nil, err
	}

	self.collection, err = ebpf.NewCollectionWithOptions(
		self.spec, ebpf.CollectionOptions{})
	if err != nil {
		return nil, err
	}

	logger.Debug("Load done in %v", time.Now().Sub(start))

	self.bpfModule = bpf.NewModule(self.collection)

	// Open the config map
	cmap := self.collection.Maps["config_map"]
	config_obj := ebpfConfigEntryT{
		TraceePid: uint32(os.Getpid()),
		Options:   optTranslateFDFilePath | optExecEnv,
	}

	// Install a noop policy to get all events.
	config_obj.PoliciesVersion = 1
	config_obj.PoliciesConfig.EnabledScopes = ^uint64(0)

	zero := uint64(0)
	err = cmap.Put(unsafe.Pointer(&zero), unsafe.Pointer(&config_obj))
	if err != nil {
		return nil, err
	}

	self.probes, err = probes.NewDefaultProbeGroup(
		self.bpfModule, false)
	if err != nil {
		return nil, err
	}

	return self, nil
}
