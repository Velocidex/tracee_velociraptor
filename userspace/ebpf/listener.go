package ebpf

import (
	"context"
	"sync"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

type listener struct {
	mu sync.Mutex

	closed      bool
	output_chan chan *ordereddict.Dict

	// Belongs to the caller of Watch()
	caller_ctx context.Context

	// Blongs to the main ownder of the EBPFManager
	global_ctx context.Context

	eid_monitored map[events.ID]bool

	count int
}

func (self *listener) GetEIDs() (res []events.ID) {
	self.mu.Lock()
	defer self.mu.Unlock()

	for eid := range self.eid_monitored {
		res = append(res, eid)
	}
	return res
}

func (self *listener) Feed(
	eid events.ID, event *ordereddict.Dict) {

	self.mu.Lock()
	defer self.mu.Unlock()

	// Ignore events not for us.
	ok, _ := self.eid_monitored[eid]
	if !ok {
		return
	}

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

	case self.output_chan <- event:
		self.count++
	}
}

func (self *listener) GetCount() int {
	self.mu.Lock()
	defer self.mu.Unlock()

	return self.count
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

func NewListner(caller_ctx, global_ctx context.Context, selected_events []events.ID) *listener {
	res := &listener{
		output_chan:   make(chan *ordereddict.Dict),
		global_ctx:    global_ctx,
		caller_ctx:    caller_ctx,
		eid_monitored: make(map[events.ID]bool),
	}

	for _, eid := range selected_events {
		res.eid_monitored[eid] = true
	}

	return res
}
