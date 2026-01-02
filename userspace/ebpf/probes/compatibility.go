package probes

type ProbeCompatibility uint64
type EnvironmentProvider int

func (self *TraceProbe) isCompatible(e EnvironmentProvider) (bool, error) {
	return false, nil
}

func (self *FixedUprobe) isCompatible(e EnvironmentProvider) (bool, error) {
	return false, nil
}

func (self *CgroupProbe) isCompatible(e EnvironmentProvider) (bool, error) {
	return false, nil
}

func NewProbeCompatibility(args ...interface{}) *ProbeCompatibility {
	res := ProbeCompatibility(0)
	return &res
}

func NewKernelVersionRequirement(args ...interface{}) int {
	return 0
}

func NewBPFMapTypeRequirement(args ...interface{}) int {
	return 0
}

func NewBPFHelperRequirement(args ...interface{}) int {
	return 0
}

func NewLsmProgramProbe(name string, f string) Probe {
	return NewTraceProbe(RawTracepoint, name, f)
}
