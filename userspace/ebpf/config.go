package ebpf

import (
	"time"
)

// options config should match defined values in ebpf code
type ConfigOptions uint32

const (
	OptExecEnv ConfigOptions = 1 << iota
	OptCaptureFilesWrite
	OptExtractDynCode
	OptStackAddresses
	OptCaptureModules
	OptCgroupV1
	OptTranslateFDFilePath
	OptCaptureBpf
	OptCaptureFileRead
	OptForkProcTree
)

type Config struct {
	Options ConfigOptions

	// How long to wait before unloading an idle program.
	IdleUnloadTimeout time.Duration
}
