// An adapter library to translate github.com/aquasecurity/libbpfgo to github.com/cilium/ebpf

package bpf

import (
	"errors"
	"fmt"

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
)

type Map struct {
	*ebpf.Map
}

func (self *Map) Update(key, value interface{}) error {
	return self.Put(key, value)
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

func (self *Program) AttachCgroupLegacy(mount_point string, attach_type BPFAttachType) (*BPFLink, error) {
	return nil, fmt.Errorf("AttachCgroupLegacy: %w", NotImplementedError)
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
	return nil, fmt.Errorf("AttachTracepoint: %w", NotImplementedError)
}

func (self *Program) AttachUprobe(pid int, path string, offset uint32) (*BPFLink, error) {
	return nil, fmt.Errorf("AttachUprobe: %w", NotImplementedError)
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
	return nil, fmt.Errorf("AttachKprobeOffset: %w", NotImplementedError)
}

func (self *Program) AttachKretprobeOnOffset(address uint64) (*BPFLink, error) {
	return nil, fmt.Errorf("AttachKretprobeOnOffset: %w", NotImplementedError)
}

func (self *Program) SetAutoload(autoload bool) error {
	return NotImplementedError
}
