package ebpf

import (
	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
)

func GetEvents() *ordereddict.Dict {
	res := ordereddict.NewDict()

	for id, desc := range events.CoreEvents {

		params := ordereddict.NewDict()
		for _, p := range desc.GetParams() {
			params.Set(p.Name, p.Type)
		}

		item := ordereddict.NewDict().
			Set("Name", desc.GetName()).
			Set("Id", int64(id)).
			Set("Sets", desc.GetSets()).
			Set("Params", params)

		res.Set(desc.GetName(), item)
	}

	return res
}
