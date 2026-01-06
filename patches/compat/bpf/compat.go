// An adapter library to translate github.com/aquasecurity/libbpfgo to github.com/cilium/ebpf

package bpf

import (
	"errors"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var (
	ProgramNotFoundError = errors.New("programNotFoundError")
	NotImplementedError  = errors.New("NotImplementedError")
)

type BPFAttachType uint32

const (
	BPFAttachTypeCgroupInetIngress BPFAttachType = 0
	BPFAttachTypeCgroupInetEgress  BPFAttachType = 1
	BPFFuncGetCurrentTaskBtf                     = "get_current_task_btf"
)

type Map struct {
	*ebpf.Map
}

func (self *Map) Update(key, value interface{}) error {
	return self.Put(key, value)
}

const (
	MapTypeArena      = ebpf.Arena
	BPFProgTypeKprobe = ebpf.Kprobe
)

type BPFMap Map
type BPFMapLow Map

// Fixme!
func (self BPFMap) GetValue(mapkey unsafe.Pointer) ([]byte, error) {
	return nil, errors.New("Not supported")
}

type BPFLink struct {
	link.Link
}

func (sef *BPFLink) Destroy() error {
	return NotImplementedError
}

type Module struct {
	collection *ebpf.Collection
}

func NewModule(collection *ebpf.Collection) *Module {
	return &Module{collection}
}

func (self *Module) GetProgram(name string) (*Program, error) {
	res, pres := self.collection.Programs[name]
	if !pres {
		return nil, ProgramNotFoundError
	}

	return &Program{res}, nil
}

func (self *Module) GetMap(name string) (*Map, error) {
	res, pres := self.collection.Maps[name]
	if !pres {
		return nil, ProgramNotFoundError
	}

	return &Map{res}, nil
}

type Program struct {
	program *ebpf.Program
}

func (self *Program) AttachGeneric() (*BPFLink, error) {
	return nil, errors.New("Not supported")
}

func (self *Program) AttachCgroupLegacy(mount_point string, attach_type BPFAttachType) (*BPFLink, error) {
	res, err := link.AttachCgroup(link.CgroupOptions{
		Path:    mount_point,
		Attach:  ebpf.AttachType(attach_type),
		Program: self.program,
	})
	return &BPFLink{res}, err
}

func (self *Program) AttachKprobe(mount_point string) (*BPFLink, error) {
	res, err := link.Kprobe(mount_point, self.program, &link.KprobeOptions{})
	return &BPFLink{res}, err
}

func (self *Program) AttachKretprobe(mount_point string) (*BPFLink, error) {
	res, err := link.Kretprobe(mount_point, self.program, &link.KprobeOptions{})
	return &BPFLink{res}, err
}

func (self *Program) AttachTracepoint(class, event string) (*BPFLink, error) {
	res, err := link.Tracepoint(class, event, self.program, nil)
	if err != nil {
		return nil, err
	}

	return &BPFLink{res}, nil
}

func (self *Program) AttachUprobe(pid int, path string, address uint64) (*BPFLink, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}

	res, err := exe.Uprobe("", self.program, &link.UprobeOptions{
		Address: uint64(address),
		PID:     pid,
	})
	return &BPFLink{res}, nil
}

func (self *Program) AttachURetprobe(pid int, path string, address uint64) (*BPFLink, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}

	res, err := exe.Uretprobe("", self.program, &link.UprobeOptions{
		Address: uint64(address),
		PID:     pid,
	})
	return &BPFLink{res}, nil
}

func (self *Program) AttachRawTracepoint(event string) (*BPFLink, error) {
	res, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    event,
		Program: self.program,
	})
	if err != nil {
		return nil, err
	}

	return &BPFLink{res}, nil
}

func (self *Program) AttachKprobeOffset(address uint64) (*BPFLink, error) {
	res, err := link.Kprobe("", self.program, &link.KprobeOptions{
		Offset: address,
	})
	if err != nil {
		return nil, err
	}
	return &BPFLink{res}, nil
}

func (self *Program) AttachKretprobeOnOffset(address uint64) (*BPFLink, error) {
	res, err := link.Kretprobe("", self.program, &link.KprobeOptions{
		Offset: address,
	})
	if err != nil {
		return nil, err
	}
	return &BPFLink{res}, nil
}

func (self *Program) SetAutoload(autoload bool) error {
	return nil
}
