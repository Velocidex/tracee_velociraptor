package manager

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Velocidex/ordereddict"
	"github.com/Velocidex/tracee_velociraptor/userspace/events"
	"github.com/Velocidex/tracee_velociraptor/userspace/events/derive"
	"github.com/Velocidex/tracee_velociraptor/userspace/types/trace"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	parsePacketError  = errors.New("Unable to parse packet")
	noPayloadError    = errors.New("noPayloadError")
	emptyPayloadError = errors.New("empty payload ?")
	nonByteArgError   = errors.New("non []byte argument ?")
)

const (
	familyIPv4 int = 1 << iota
	familyIPv6
)

// getLayer3TypeFlagFromEvent returns the layer 3 protocol type from a given event.
func getLayer3TypeFlagFromEvent(event *trace.Event) (gopacket.LayerType, error) {
	switch {
	case event.ReturnValue&familyIPv4 == familyIPv4:
		return layers.LayerTypeIPv4, nil
	case event.ReturnValue&familyIPv6 == familyIPv6:
		return layers.LayerTypeIPv6, nil
	}
	return 0, fmt.Errorf("wrong layer 3 ret value flag")
}

func NetPacketParsedDeriver() derive.DeriveFunction {
	return func(event *trace.Event) ([]trace.Event, []error) {
		payload, err := parsePayloadArg(event)
		if err != nil {
			return nil, []error{err}
		}

		layer3Type, err := getLayer3TypeFlagFromEvent(event)
		if err != nil {
			return nil, []error{err}
		}

		packet := gopacket.NewPacket(
			payload,
			layer3Type,
			gopacket.NoCopy,
		)
		if packet == nil {
			return nil, []error{parsePacketError}
		}

		result := ordereddict.NewDict()
		var last_payload []byte
		for _, layer := range packet.Layers() {
			// Convert the layer to a dict.
			serialized, err := json.Marshal(layer)
			if err != nil {
				continue
			}

			res := ordereddict.NewDict()
			err = res.UnmarshalJSON(serialized)
			if err != nil {
				continue
			}

			res.Delete("Contents")
			res.Delete("Payload")
			res.Delete("Padding")

			result.Set(layer.LayerType().String(), res)
			last_payload = layer.LayerPayload()
		}

		result.Set("FinalPayload", last_payload)

		return []trace.Event{trace.Event{
			Args: []trace.Argument{
				trace.Argument{
					ArgMeta: trace.ArgMeta{
						Name: "packet",
					},
					Value: result,
				}}},
		}, nil
	}
}

// parsePayloadArg returns the packet payload from the event.
func parsePayloadArg(event *trace.Event) ([]byte, error) {
	payloadArg := events.GetArg(event.Args, "payload")
	if payloadArg == nil {
		return nil, noPayloadError
	}
	payload, ok := payloadArg.Value.([]byte)
	if !ok {
		return nil, nonByteArgError
	}
	payloadSize := len(payload)
	if payloadSize < 1 {
		return nil, emptyPayloadError
	}
	return payload, nil
}
