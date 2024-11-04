package ebpf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/Velocidex/tracee_velociraptor/userspace/bufferdecoder"
	"github.com/Velocidex/tracee_velociraptor/userspace/compat/bpf"
	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/probes"
	"github.com/Velocidex/tracee_velociraptor/userspace/time"
	"github.com/Velocidex/tracee_velociraptor/userspace/types/trace"
	"github.com/Velocidex/tracee_velociraptor/userspace/utils"
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

	fmt.Printf("Required KSyms %v\n", res)
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

	fmt.Printf("Monitoring Handles %v\n", res)
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
				fmt.Printf("setTailCalls: Set %v to %v in %v\n",
					tailCall.GetMapName(),
					tailCall.GetProgName(),
					idx)
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
		fmt.Printf("Monitoring EID %v\n", key)
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
		self.collection.Close()
	}
}

func (self *EBPFManager) Watch(ctx context.Context) error {

	err := self.populateBPFMaps()
	if err != nil {
		return err
	}

	defer self.probes.DetachAll()

	kernelSymbols, err := environment.NewKernelSymbolTable(
		environment.WithRequiredSymbols(self.getRequiredKsyms()),
	)

	for _, handle := range self.getProbeHandles() {
		err := self.probes.Attach(handle, kernelSymbols)
		if err != nil {
			fmt.Printf("Error attaching %v: %v\n", handle, err)
			continue
		}
	}

	rd, err := perf.NewReader(self.collection.Maps["events"], 32*4096)
	if err != nil {
		return err
	}
	defer rd.Close()

	fmt.Printf("Reading events\n")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return err
			}
			continue
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			continue
		}

		serialized, err := json.Marshal(event)
		if err != nil {
			continue
		}

		fmt.Println(string(serialized))
		//fmt.Println(hex.Dump(record.RawSample))
	}

	return nil
}

func NewEBPFManager() (*EBPFManager, error) {
	self := &EBPFManager{
		policy_id:     1,
		eid_monitored: make(map[events.ID]bool),
	}

	// Set the clocks and initialize.
	time.Init(unix.CLOCK_BOOTTIME)

	fmt.Printf("Starting\n")

	// Allow the current process to lock memory for eBPF resources.
	err := rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	self.spec, err = loadEbpf()
	if err != nil {
		return nil, err
	}

	self.collection, err = ebpf.NewCollectionWithOptions(self.spec,
		ebpf.CollectionOptions{})
	if err != nil {
		return nil, err
	}

	self.bpfModule = bpf.NewModule(self.collection)

	// Open the config map
	cmap := self.collection.Maps["config_map"]
	config_obj := ebpfConfigEntryT{
		TraceePid: uint32(os.Getpid()),
		Options:   optTranslateFDFilePath | optExecEnv, // | optForkProcTree,
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

func decodeEvent(dataRaw []byte) (*trace.Event, error) {
	ebpfMsgDecoder := bufferdecoder.New(dataRaw)
	var eCtx bufferdecoder.EventContext

	err := ebpfMsgDecoder.DecodeContext(&eCtx)
	if err != nil {
		return nil, err
	}

	var argnum uint8
	err = ebpfMsgDecoder.DecodeUint8(&argnum)
	if err != nil {
		return nil, err
	}

	eventId := events.ID(eCtx.EventID)
	if !events.Core.IsDefined(eventId) {
		return nil, errfmt.Errorf("failed to get configuration of event %d", eventId)
	}
	eventDefinition := events.Core.GetDefinitionByID(eventId)
	evtParams := eventDefinition.GetParams()
	evtName := eventDefinition.GetName()
	args := make([]trace.Argument, len(evtParams))
	err = ebpfMsgDecoder.DecodeArguments(args, int(argnum), evtParams, evtName, eventId)
	if err != nil {
		return nil, err
	}

	// Add stack trace if needed
	var stackAddresses []uint64
	//	if t.config.Output.StackAddresses {
	//	stackAddresses = t.getStackAddresses(eCtx.StackID)
	// }
	/*
			containerInfo := t.containers.GetCgroupInfo(eCtx.CgroupID).Container
			containerData := trace.Container{
				ID:          containerInfo.ContainerId,
				ImageName:   containerInfo.Image,
				ImageDigest: containerInfo.ImageDigest,
				Name:        containerInfo.Name,
			}
			kubernetesData := trace.Kubernetes{
				PodName:      containerInfo.Pod.Name,
				PodNamespace: containerInfo.Pod.Namespace,
				PodUID:       containerInfo.Pod.UID,
			}

		flags := parseContextFlags(containerData.ID, eCtx.Flags)
		syscall := ""
		if eCtx.Syscall != noSyscall {
			var err error
			syscall, err = parseSyscallID(int(eCtx.Syscall), flags.IsCompat, sysCompatTranslation)
			if err != nil {
				//logger.Debugw("Originated syscall parsing", "error", err)
			}
		}

		// get an event pointer from the pool
		evt, ok := t.eventsPool.Get().(*trace.Event)
		if !ok {
			t.handleError(errfmt.Errorf("failed to get event from pool"))
			continue
		}
	*/

	evt := &trace.Event{}

	// populate all the fields of the event used in this stage, and reset the rest

	// normalize timestamp context fields for later use
	normalizedTs := time.BootToEpochNS(eCtx.Ts)
	normalizedThreadStartTime := time.BootToEpochNS(eCtx.StartTime)
	normalizedLeaderStartTime := time.BootToEpochNS(eCtx.LeaderStartTime)
	normalizedParentStartTime := time.BootToEpochNS(eCtx.ParentStartTime)

	evt.Timestamp = int(normalizedTs)
	evt.ThreadStartTime = int(normalizedThreadStartTime)
	evt.ProcessorID = int(eCtx.ProcessorId)
	evt.ProcessID = int(eCtx.Pid)
	evt.ThreadID = int(eCtx.Tid)
	evt.ParentProcessID = int(eCtx.Ppid)
	evt.HostProcessID = int(eCtx.HostPid)
	evt.HostThreadID = int(eCtx.HostTid)
	evt.HostParentProcessID = int(eCtx.HostPpid)
	evt.UserID = int(eCtx.Uid)
	evt.MountNS = int(eCtx.MntID)
	evt.PIDNS = int(eCtx.PidID)
	evt.ProcessName = string(bytes.TrimRight(eCtx.Comm[:], "\x00")) // set and clean potential trailing null
	evt.HostName = string(bytes.TrimRight(eCtx.UtsName[:], "\x00")) // set and clean potential trailing null
	evt.CgroupID = uint(eCtx.CgroupID)
	//evt.ContainerID = containerData.ID
	//evt.Container = containerData
	//evt.Kubernetes = kubernetesData
	evt.EventID = int(eCtx.EventID)
	evt.EventName = evtName
	evt.PoliciesVersion = eCtx.PoliciesVersion
	evt.MatchedPoliciesKernel = eCtx.MatchedPolicies
	evt.MatchedPoliciesUser = 0
	evt.MatchedPolicies = []string{}
	evt.ArgsNum = int(argnum)
	evt.ReturnValue = int(eCtx.Retval)
	evt.Args = args
	evt.StackAddresses = stackAddresses
	//evt.ContextFlags = flags
	//evt.Syscall = syscall
	evt.Metadata = nil
	evt.ThreadEntityId = utils.HashTaskID(eCtx.HostTid, normalizedThreadStartTime)
	evt.ProcessEntityId = utils.HashTaskID(eCtx.HostPid, normalizedLeaderStartTime)
	evt.ParentEntityId = utils.HashTaskID(eCtx.HostPpid, normalizedParentStartTime)

	return evt, nil
}
