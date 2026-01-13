package manager

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Velocidex/tracee_velociraptor/userspace/cmd/flags"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	k8s "github.com/Velocidex/tracee_velociraptor/userspace/k8s/apis/tracee.aquasec.com/v1beta1"
	"github.com/Velocidex/tracee_velociraptor/userspace/policy/v1beta1"
	"gopkg.in/yaml.v2"
)

func PolicyFromString(in string) (res k8s.PolicyInterface, err error) {
	in = strings.TrimSpace(in)
	if len(in) == 0 {
		return nil, errors.New("Invalid policy")
	}

	var p v1beta1.PolicyFile

	// JSON type
	if in[0] == '{' {
		err = json.Unmarshal([]byte(in), &p)
	} else {
		err = yaml.Unmarshal([]byte(in), &p)
	}
	if err != nil {
		return nil, err
	}

	// We dont care about some fields to make the policy definitions a
	// bit simpler.
	p.APIVersion = "tracee.aquasec.com/v1beta1"
	p.Kind = "Policy"

	err = p.Validate()
	if err != nil {
		return p, err
	}

	return p, nil
}

func EventIDsForPolicy(p k8s.PolicyInterface) ([]events.ID, error) {
	scope_map, event_map, err := flags.PrepareFilterMapsFromPolicies(
		[]k8s.PolicyInterface{p})
	if err != nil {
		return nil, err
	}

	ps, err := flags.CreatePolicies(scope_map, event_map)
	if err != nil {
		return nil, err
	}

	var events []events.ID
	for _, p := range ps {
		for e := range p.Rules {
			events = append(events, e)
		}
	}
	return events, nil
}
