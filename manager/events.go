package manager

import (
	"bytes"
	"time"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/bufferdecoder"
	"github.com/Velocidex/tracee_velociraptor/userspace/errfmt"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	time_utils "github.com/Velocidex/tracee_velociraptor/userspace/time"
	"github.com/Velocidex/tracee_velociraptor/userspace/types/trace"
)

// Velociraptor Specific Events
const (
	NetPacketParsed events.ID = iota + 100000
)

var CoreEvents = map[events.ID]events.Definition{}

type eventType struct {
	*ordereddict.Dict

	System *ordereddict.Dict
	tevent *trace.Event
}

func (self *EBPFManager) decodeEvent(dataRaw []byte) (*eventType, events.ID, error) {
	ebpfMsgDecoder := bufferdecoder.New(dataRaw, self.dataTypeDecoder)
	var eCtx bufferdecoder.EventContext

	err := ebpfMsgDecoder.DecodeContext(&eCtx)
	if err != nil {
		return nil, 0, err
	}

	var argnum uint8
	err = ebpfMsgDecoder.DecodeUint8(&argnum)
	if err != nil {
		return nil, 0, err
	}

	eventId := events.ID(eCtx.EventID)
	eventDefinition := events.Core.GetDefinitionByID(eventId)
	if eventDefinition.NotValid() {
		return nil, 0, errfmt.Errorf(
			"failed to get configuration of event %d", eventId)
	}

	evtFields := eventDefinition.GetFields()
	evtName := eventDefinition.GetName()

	args := make([]trace.Argument, len(evtFields))
	err = ebpfMsgDecoder.DecodeArguments(args, int(argnum), evtFields,
		evtName, eventId)
	if err != nil {
		return nil, 0, err
	}

	event_data := ordereddict.NewDict()
	for _, arg := range args {
		event_data.Set(arg.Name, arg.Value)
	}

	// normalize timestamp context fields for later use
	normalizedTs := time_utils.BootToEpochNS(eCtx.Ts)
	normalizedThreadStartTime := time_utils.BootToEpochNS(eCtx.StartTime)

	// Divide the event into two parts - the System part contains all
	// common fields. The EventData part contain all variable fields.
	system_part := ordereddict.NewDict().
		Set("Timestamp", time.Unix(0, int64(normalizedTs))).
		Set("EventID", eCtx.EventID).
		Set("EventName", evtName).
		Set("ThreadStartTime", time.Unix(0, int64(normalizedThreadStartTime))).
		Set("ProcessorID", eCtx.ProcessorId).
		Set("ProcessID", eCtx.Pid).
		Set("ThreadID", eCtx.Tid).
		Set("ParentProcessID", eCtx.Ppid).
		Set("HostProcessID", eCtx.HostPid).
		Set("HostThreadID", eCtx.HostTid).
		Set("HostParentProcessID", eCtx.HostPpid).
		Set("UserID", eCtx.Uid).
		Set("MountNS", eCtx.MntID).
		Set("ProcessName", string(bytes.TrimRight(eCtx.Comm[:], "\x00"))).
		Set("HostName", string(bytes.TrimRight(eCtx.UtsName[:], "\x00"))).
		Set("CgroupID", eCtx.CgroupID)

	return &eventType{
		Dict: ordereddict.NewDict().
			Set("System", system_part).
			Set("EventData", event_data),
		System: system_part,
		tevent: &trace.Event{
			// Events are pre-processed in the ebpf code and we need
			// to examine these fields in derivers.
			ReturnValue: int(eCtx.Retval),
			Args:        args,
		},
	}, eCtx.EventID, nil
}

func init() {
	// Copy the Core events to our own set
	for k, v := range events.CoreEvents {
		CoreEvents[k] = v
	}
}
