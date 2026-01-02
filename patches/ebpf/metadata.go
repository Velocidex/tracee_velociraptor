package ebpf

import (
	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

func getEventFromDesc(desc events.Definition) *ordereddict.Dict {
	params := ordereddict.NewDict()
	for _, p := range desc.GetFields() {
		params.Set(p.Name, p.Type)
	}

	item := ordereddict.NewDict().
		Set("Name", desc.GetName()).
		Set("Id", int64(desc.GetID())).
		Set("Sets", desc.GetSets()).
		Set("Params", params)

	return item
}

func GetEvents() *ordereddict.Dict {
	res := ordereddict.NewDict()

	for _, desc := range CoreEvents {
		res.Set(desc.GetName(), getEventFromDesc(desc))
	}

	return res
}

func DescByEventName(name string) (*ordereddict.Dict, bool) {
	for id, desc := range CoreEvents {
		if desc.GetName() == name {
			params := ordereddict.NewDict()
			for _, p := range desc.GetFields() {
				params.Set(p.Name, p.Type)
			}

			return ordereddict.NewDict().
				Set("Name", desc.GetName()).
				Set("Id", int64(id)).
				Set("Sets", desc.GetSets()).
				Set("Params", params), true
		}
	}
	return nil, false
}
