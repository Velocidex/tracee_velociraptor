//go:build mage
// +build mage

package main

import (
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type Builder struct{}

func (self *Builder) Env() map[string]string {
	env := make(map[string]string)
	env["GOPACKAGE"] = "ebpf"
	return env
}

func (self *Builder) cwd(dir string) (func(), error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	err = os.Chdir(dir)
	if err != nil {
		return nil, err
	}

	return func() {
		os.Chdir(cwd)
	}, nil
}

func (self *Builder) Bin() error {
	return sh.RunWith(self.Env(), mg.GoCmd(), "build",
		"-o", "./test",
		"./userspace/cmd/",
	)
}

func (self *Builder) Generate() error {
	closer, err := self.cwd("userspace/ebpf")
	if err != nil {
		return err
	}
	defer closer()

	return sh.RunWith(self.Env(), mg.GoCmd(), "run",
		"github.com/cilium/ebpf/cmd/bpf2go",
		"-type", "config_entry_t",
		"-type", "event_context_t",
		"-type", "event_config_t",
		"-no-global-types",
		"-target", "bpfel",
		"ebpf", "../../tracee.bpf.c",
		"--", "-I../../", "-D__TARGET_ARCH_x86", "-DDEBUG_K",
	)
}

// Build ebpf files
func Generate() error {
	builder := Builder{}

	return builder.Generate()
}

func Bin() error {
	builder := Builder{}
	return builder.Bin()
}
