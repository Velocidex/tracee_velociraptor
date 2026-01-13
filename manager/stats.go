package manager

import (
	"time"

	k8s "github.com/Velocidex/tracee_velociraptor/userspace/k8s/apis/tracee.aquasec.com/v1beta1"
)

type ListenerStats struct {
	PolicyID     int
	Policy       k8s.PolicyInterface
	EIDMonitored []string

	// Events fed to this listener.
	EventCount int
}

type Stats struct {
	Listeners []ListenerStats

	IdleTime          time.Duration
	IdleUnloadTimeout time.Duration

	EBFProgramStatus string

	// Total event seen before prefilter
	PrefilterEventCount int

	// Total events parsed
	EventCount int
}

func (self *listener) Stats() ListenerStats {
	self.mu.Lock()
	defer self.mu.Unlock()

	res := ListenerStats{
		PolicyID:   self.policy_id,
		Policy:     self.policy,
		EventCount: self.count,
	}

	for k := range self.eid_monitored {
		desc, pres := CoreEvents[k]
		if !pres {
			continue
		}

		res.EIDMonitored = append(res.EIDMonitored, desc.GetName())
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

	res.IdleTime = time.Now().Sub(self.idle_time)
	res.IdleUnloadTimeout = self.idle_unload_time

	for _, listener := range self.listeners {
		res.Listeners = append(res.Listeners, listener.Stats())
		res.EventCount += listener.GetCount()
		res.PrefilterEventCount += listener.GetPrefilterEvents()
	}
	return res
}
