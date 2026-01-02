package ebpf

import (
	"context"
	"sync"

	"github.com/Velocidex/ordereddict"
	dnscache "github.com/Velocidex/tracee_velociraptor/userspace/datastores/dns"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/events/derive"
)

type Action bool

const (
	ForwardEvent  Action = true
	SuppressEvent Action = false
)

type derivedEvent struct {
	eid      events.ID
	eid_name string
	deriver  derive.DeriveFunction
}

type listener struct {
	mu sync.Mutex

	closed      bool
	output_chan chan *ordereddict.Dict

	// Belongs to the caller of Watch()
	caller_ctx context.Context

	// Belongs to the main owner of the EBPFManager
	global_ctx context.Context

	eid_monitored map[events.ID]Action

	dnscache *dnscache.DNSCache

	derivation map[events.ID][]derivedEvent

	// Total events we considered
	prefilter_count int

	// Total events parsed (after prefilter accepted)
	count int

	logger Logger

	prefilter func(buf []byte) bool
}

func (self *listener) SetPrefilter(filter func(in []byte) bool) {
	self.prefilter = filter
}

func (self *listener) Prefilter(in []byte) bool {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.prefilter_count++
	if self.prefilter == nil {
		return true
	}

	return self.prefilter(in)
}

func (self *listener) maybeAddDerivation(
	eid events.ID, derivation derive.DeriveFunction,
	res []derivedEvent) []derivedEvent {
	_, pres := self.eid_monitored[eid]
	if !pres {
		return res
	}

	desc, pres := CoreEvents[eid]
	if !pres {
		return res
	}

	return append(res, derivedEvent{
		eid:      eid,
		eid_name: desc.GetName(),
		deriver:  derivation,
	})
}

func (self *listener) buildDerivationTable() map[events.ID][]derivedEvent {
	result := map[events.ID][]derivedEvent{}

	var res []derivedEvent

	for eid := range self.eid_monitored {
		switch eid {
		case events.NetPacketRaw:
			res = self.maybeAddDerivation(NetPacketParsed, NetPacketParsedDeriver(), res)
			result[eid] = res

		case events.NetPacketIPBase:
			res = self.maybeAddDerivation(events.NetPacketIPv4, derive.NetPacketIPv4(), res)
			res = self.maybeAddDerivation(events.NetPacketIPv6, derive.NetPacketIPv6(), res)
			result[eid] = res

		case events.NetPacketTCPBase:
			res = self.maybeAddDerivation(events.NetPacketTCP,
				derive.NetPacketTCP(), nil)
			result[eid] = res

		case events.NetPacketUDPBase:
			res = self.maybeAddDerivation(events.NetPacketUDP,
				derive.NetPacketUDP(), nil)
			result[eid] = res

		case events.NetPacketICMPBase:
			res = self.maybeAddDerivation(events.NetPacketICMP,
				derive.NetPacketICMP(), nil)
			result[eid] = res

		case events.NetPacketICMPv6Base:
			res = self.maybeAddDerivation(events.NetPacketICMPv6,
				derive.NetPacketICMPv6(), nil)
			result[eid] = res

		case events.NetPacketDNSBase:
			res = self.maybeAddDerivation(events.NetPacketDNS,
				derive.NetPacketDNS(), nil)
			res = self.maybeAddDerivation(events.NetPacketDNSRequest,
				derive.NetPacketDNSRequest(), res)
			res = self.maybeAddDerivation(events.NetPacketDNSResponse,
				derive.NetPacketDNSResponse(), res)
			result[eid] = res

		case events.NetPacketHTTPBase:
			res = self.maybeAddDerivation(events.NetPacketHTTP,
				derive.NetPacketHTTP(), nil)
			res = self.maybeAddDerivation(events.NetPacketHTTPRequest,
				derive.NetPacketHTTPRequest(), res)
			res = self.maybeAddDerivation(events.NetPacketHTTPResponse,
				derive.NetPacketHTTPResponse(), res)
			result[eid] = res

		case events.NetPacketFlowBase:
			res = self.maybeAddDerivation(events.NetFlowTCPBegin,
				derive.NetFlowTCPBegin(self.dnscache), nil)
			res = self.maybeAddDerivation(events.NetFlowTCPEnd,
				derive.NetFlowTCPEnd(self.dnscache), res)
			result[eid] = res
		}
	}

	return result
}

// Pull in dependencies of
func (self *listener) addDependency(eid events.ID) {
	desc, pres := CoreEvents[eid]
	if !pres {
		return
	}

	for _, dep := range desc.GetDependencies().
		GetPrimaryDependencies().GetIDs() {
		_, pres := self.eid_monitored[eid]
		if !pres {
			continue
		}

		// Dependency is not requested but we need it to fill the
		// requested eid, so set it with an action of suppress
		self.eid_monitored[dep] = SuppressEvent

		// Recurse for more depds
		self.addDependency(dep)
	}
}

func (self *listener) GetEIDs() (res []events.ID) {
	self.mu.Lock()
	defer self.mu.Unlock()

	for eid := range self.eid_monitored {
		res = append(res, eid)
	}
	return res
}

// Derivations are functions that produce derived events
// (i.e. additional events) from the base event.
func (self *listener) feedDerivations(
	eid events.ID, event *eventType) {

	derivations, pres := self.derivation[eid]
	if !pres {
		return
	}

	for _, d := range derivations {
		derived, _ := d.deriver(event.tevent)
		for _, derived_event := range derived {
			system_part := ordereddict.NewDict()
			system_part.MergeFrom(event.System)

			system_part.Update("EventID", d.eid).
				Update("EventName", d.eid_name)

			event_data := ordereddict.NewDict()
			for _, arg := range derived_event.Args {
				event_data.Set(arg.Name, arg.Value)
			}

			new_event := ordereddict.NewDict().
				Set("System", system_part).
				Set("EventData", event_data)

			self.feed(d.eid, &eventType{
				Dict: new_event,
			})
		}
	}

}

func (self *listener) Feed(
	eid events.ID, event *eventType) {

	self.mu.Lock()
	defer self.mu.Unlock()

	// Ignore events not for us.
	action, pres := self.eid_monitored[eid]

	// Ignore this event - we dont care about it.
	if !pres {
		return
	}

	// Any derivations?
	self.feedDerivations(eid, event)

	if action == ForwardEvent {
		self.feed(eid, event)
	}
}

func (self *listener) feed(
	eid events.ID, event *eventType) {

	if self.closed {
		return
	}

	select {
	case <-self.caller_ctx.Done():
		self.close()
		return

	case <-self.global_ctx.Done():
		self.close()
		return

	case self.output_chan <- event.Dict:
		self.count++
	}
}

func (self *listener) GetCount() int {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self.count
}

func (self *listener) GetPrefilterEvents() int {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self.prefilter_count
}

func (self *listener) Close() {
	self.mu.Lock()
	defer self.mu.Unlock()

	self.close()
}

func (self *listener) close() {
	if !self.closed {
		close(self.output_chan)
		self.closed = true
	}
}

func NewListner(
	logger Logger, dnscache *dnscache.DNSCache,
	caller_ctx, global_ctx context.Context,
	selected_events []events.ID) *listener {
	res := &listener{
		output_chan:   make(chan *ordereddict.Dict),
		global_ctx:    global_ctx,
		caller_ctx:    caller_ctx,
		eid_monitored: make(map[events.ID]Action),
	}

	for _, eid := range selected_events {
		res.eid_monitored[eid] = ForwardEvent
	}

	for _, eid := range selected_events {
		res.addDependency(eid)
	}

	res.derivation = res.buildDerivationTable()

	return res
}
