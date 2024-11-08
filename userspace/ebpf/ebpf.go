package ebpf

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/bufferdecoder"
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
	mu sync.Mutex

	ctx    context.Context
	cancel func()

	spec              *ebpf.CollectionSpec
	collection        *ebpf.Collection
	currently_loading bool

	policy_id uint16

	probes *probes.ProbeGroup

	bpfModule *bpf.Module

	KernelConfig *environment.KernelConfig

	eventsParamTypes map[events.ID][]bufferdecoder.ArgType

	logger Logger

	// A list of listeners - we multiplex the event stream to all
	// listeners.
	listeners []*listener

	ebpf_config_obj ebpfConfigEntryT

	// We do not unload the program immediately. Instead we count when
	// the manager is idle and only unload the ebpf program after some
	// time. The manager will load the program on demand in the
	// future.
	idle_time        time.Time
	idle_unload_time time.Duration
}

func (self *EBPFManager) EidMonitored() []events.ID {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self._EidMonitored()
}

func (self *EBPFManager) _EidMonitored() []events.ID {

	eid_monitored := make(map[events.ID]bool)
	for _, listener := range self.listeners {
		for _, eid := range listener.GetEIDs() {
			eid_monitored[eid] = true
		}
	}

	res := make([]events.ID, 0, len(eid_monitored))
	for eid := range eid_monitored {
		res = append(res, eid)
	}

	return res
}

func (self *EBPFManager) Stats() (res Stats) {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.currently_loading {
		res.EBFProgramStatus = "Currently Loading"

	} else if self.collection == nil {
		res.EBFProgramStatus = "Unloaded"

	} else {
		res.EBFProgramStatus = "Loaded"
	}

	res.NumberOfListeners = len(self.listeners)
	res.IdleTime = time.Now().Sub(self.idle_time)
	res.IdleUnloadTimeout = self.idle_unload_time

	for _, listener := range self.listeners {
		eid_monitored := make(map[string]int)

		for _, k := range listener.GetEIDs() {
			desc, pres := events.CoreEvents[k]
			if !pres {
				continue
			}

			eid_monitored[desc.GetName()] = int(k)
		}
		res.EIDMonitored = append(res.EIDMonitored, eid_monitored)
		res.EventCount += listener.GetCount()
	}
	return res
}

// Read all events from the queue and forward to all listeners.
func (self *EBPFManager) EventLoop(ctx context.Context) {
	self.mu.Lock()
	if self.collection == nil {
		self.mu.Unlock()
		return
	}

	rd, err := perf.NewReader(self.collection.Maps["events"], 32*4096)
	self.mu.Unlock()

	if err != nil {
		self.logger.Error("EBPFManager.eventLoop: %v", err)
		return
	}
	defer rd.Close()

	// Close the reader as soon as the context is done.
	go func() {
		<-ctx.Done()

		rd.Close()
	}()

	self.logger.Debug("EventLoop: Reading ebpf events")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		self.mu.Lock()
		listeners := self.listeners
		self.mu.Unlock()

		// No listeners - dont bother about it.
		if len(listeners) == 0 {
			continue
		}

		event, eid, err := decodeEvent(record.RawSample)
		if err != nil {
			continue
		}

		for _, listener := range listeners {
			listener.Feed(eid, event)
		}
	}
}

func (self *EBPFManager) startHousekeeping(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			self.UnloadEbpf()
			return

		case <-time.After(time.Second):
			self.mu.Lock()
			is_idle := len(self.listeners) == 0

			if is_idle && time.Now().
				Add(-self.idle_unload_time).
				After(self.idle_time) {
				self.unloadEbpf()
			}
			self.mu.Unlock()
		}
	}
}

func (self *EBPFManager) getRequiredKsyms() (res []string) {
	tmp := make(map[string]bool)
	for _, eid := range self._EidMonitored() {
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

	return res
}

func (self *EBPFManager) getProbeHandles() (res []probes.Handle) {
	tmp := make(map[probes.Handle]bool)
	for _, eid := range self._EidMonitored() {
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

func (self *EBPFManager) setTailCalls() error {
	for _, eid := range self._EidMonitored() {
		err := self.setTailCall(eid, tailCallsAdd)
		if err != nil {
			return err
		}
	}

	return self.setEventIDPolicy()
}

func (self *EBPFManager) setTailCall(eid events.ID, remove bool) error {
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

func (self *EBPFManager) setEventIDPolicy() error {

	var event_inner_map *ebpf.Map

	// The events_map_version is an inner map - we always renew it
	// with a new map so we can easily account for events added and
	// removed.
	map_spec, pres := self.spec.Maps["events_map_version"]
	if !pres {
		return mapNotValid
	}

	event_inner_map, err := ebpf.NewMap(map_spec.InnerMap)
	if err != nil {
		return err
	}

	for _, key := range self._EidMonitored() {
		eid := key

		event_config := &ebpfEventConfigT{
			SubmitForPolicies: uint64(self.policy_id),
		}

		params, pres := self.eventsParamTypes[eid]
		if pres {
			for n, paramType := range params {
				event_config.ParamTypes |= (uint64(paramType) << (8 * n))
			}
		}

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

func (self *EBPFManager) Close() {}

func (self *EBPFManager) applyConfig() (err error) {
	// Open the config map
	cmap := self.collection.Maps["config_map"]
	zero := uint64(0)
	err = cmap.Put(unsafe.Pointer(&zero), unsafe.Pointer(&self.ebpf_config_obj))
	if err != nil {
		return err
	}
	return nil
}

func (self *EBPFManager) UnloadEbpf() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.unloadEbpf()
}

func (self *EBPFManager) unloadEbpf() {
	if self.collection == nil {
		return
	}

	self.logger.Debug("Unloading eBPF program")
	self.cancel()

	// Close all our listers
	for _, listener := range self.listeners {
		listener.Close()
	}

	self.probes.DetachAll()
	self.collection.Close()
	self.collection = nil
}

func (self *EBPFManager) loadEbpf() (err error) {
	if self.collection != nil {
		return nil
	}

	self.currently_loading = true

	start := time.Now()
	self.logger.Debug("Loading EBPF program into kernel (This could take a while!)")
	self.spec, err = loadEbpf()
	if err != nil {
		return
	}

	self.collection, err = ebpf.NewCollectionWithOptions(
		self.spec, ebpf.CollectionOptions{})
	if err != nil {
		return
	}

	self.logger.Debug("Load done in %v", time.Now().Sub(start))

	self.currently_loading = false
	self.bpfModule = bpf.NewModule(self.collection)
	self.probes, err = probes.NewDefaultProbeGroup(
		self.bpfModule, false)
	if err != nil {
		return err
	}

	return nil
}

func (self *EBPFManager) updateEbpfState() (err error) {
	err = self.applyConfig()
	if err != nil {
		return err
	}

	err = self.setTailCalls()
	if err != nil {
		return err
	}

	err = self.populateBPFMaps()
	if err != nil {
		return err
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

	// Start the main event loop.
	sub_ctx, cancel := context.WithCancel(self.ctx)
	self.cancel = cancel
	go self.EventLoop(sub_ctx)

	return err
}

func (self *EBPFManager) Watch(
	ctx context.Context,
	selected_events []events.ID) (
	chan *ordereddict.Dict, func(), error) {

	self.mu.Lock()
	defer self.mu.Unlock()

	// Add a new listener to the event loop.
	new_listener := NewListner(ctx, self.ctx, selected_events)
	self.listeners = append(self.listeners, new_listener)

	// If the program is not already loaded, start it.
	if self.collection == nil {
		err := self.loadEbpf()
		if err != nil {
			self.listeners = nil
			return nil, nil, err
		}
	}

	// Update the ebpf state to reflect the new listene
	err := self.updateEbpfState()
	if err != nil {
		self.listeners = nil
		return nil, nil, err
	}

	return new_listener.output_chan,

		// Remove the output chan from the listeners.
		func() {
			self.mu.Lock()
			defer self.mu.Unlock()

			new_listener.Close()

			var new_listeners []*listener

			for _, d := range self.listeners {
				if d == new_listener {
					continue
				}
				new_listeners = append(new_listeners, d)
			}

			self.listeners = new_listeners

			// We are now idle.
			if len(new_listeners) == 0 {
				self.idle_time = time.Now()
			}
		}, nil
}

func NewEBPFManager(
	ctx context.Context,
	config Config,
	logger Logger) (*EBPFManager, error) {

	config_obj := ebpfConfigEntryT{
		TraceePid: uint32(os.Getpid()),
		Options:   uint32(config.Options),
	}

	// Install a noop policy to get all events.
	config_obj.PoliciesVersion = 1
	config_obj.PoliciesConfig.EnabledScopes = ^uint64(0)

	// Load the kernel config
	kernelConfig, err := environment.InitKernelConfig()
	if err != nil {
		return nil, err
	}

	self := &EBPFManager{
		policy_id:        1,
		logger:           logger,
		ebpf_config_obj:  config_obj,
		idle_unload_time: config.IdleUnloadTimeout,
		ctx:              ctx,
		KernelConfig:     kernelConfig,
		eventsParamTypes: make(map[events.ID][]bufferdecoder.ArgType),
	}

	if self.idle_unload_time == 0 {
		self.idle_unload_time = time.Duration(5 * time.Minute)
	}

	// Initialize the event parameter types
	for _, eventDefinition := range events.Core.GetDefinitions() {
		id := eventDefinition.GetID()
		params := eventDefinition.GetParams()
		for _, param := range params {
			self.eventsParamTypes[id] = append(self.eventsParamTypes[id],
				bufferdecoder.GetParamType(param.Type))
		}
	}

	// Set the clocks and initialize.
	time_util.Init(unix.CLOCK_BOOTTIME)

	// Allow the current process to lock memory for eBPF resources.
	err = rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	// Record the last time we were idle
	self.idle_time = time.Now()
	go self.startHousekeeping(ctx)

	return self, nil
}
