//go:build mage
// +build mage

package main

import (
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	"github.com/Velocidex/tracee_velociraptor/mutations"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type Builder struct{}

func (self *Builder) Env() map[string]string {
	env := make(map[string]string)
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

func (self *Builder) Race() error {
	return sh.RunWith(self.Env(), mg.GoCmd(), "build",
		"-o", "./test", "-race",
		"./userspace/cmd/",
	)
}

func (self *Builder) Generate() error {
	err := self.generate()
	if err != nil {
		return err
	}

	return self.fixAssets()
}

func (self *Builder) generate() error {
	closer, err := self.cwd("manager")
	if err != nil {
		return err
	}
	defer closer()

	if runtime.GOARCH == "amd64" {
		return sh.RunWith(self.Env(), mg.GoCmd(), "run",
			"github.com/cilium/ebpf/cmd/bpf2go",
			"-type", "config_entry_t",
			"-type", "event_context_t",
			"-type", "event_config_t",
			"-no-global-types",
			"-target", "bpfel",
			"-go-package", "manager",
			"ebpf", "../c/tracee.bpf.c",
			"--", "-I../c/", "-D__TARGET_ARCH_x86", "-DDEBUG_K",
		)

	} else if runtime.GOARCH == "arm64" {
		return sh.RunWith(self.Env(), mg.GoCmd(), "run",
			"github.com/cilium/ebpf/cmd/bpf2go",
			"-type", "config_entry_t",
			"-type", "event_context_t",
			"-type", "event_config_t",
			"-no-global-types",
			"-target", "bpfel",
			"-go-package", "manager",
			"ebpf", "../c/tracee.bpf.c",
			"--", "-I../c/", "-D__TARGET_ARCH_arm64", "-DDEBUG_K",
		)

	} else {
		panic("Architecture not supported!")
	}

}

func (self *Builder) fixAssets() error {
	// We only use little endian for the moment
	for _, f := range []string{
		"manager/manager_bpfel.go",
	} {
		replace_string_in_file(f, `//go:embed `, "//")
		replace_string_in_file(f, `bytes.NewReader(_EbpfBytes)`,
			`bytes.NewReader(getEbpfBytes())`)
	}

	if runtime.GOARCH == "amd64" {
		err := fileb0x("manager/b0x_bpfel_amd64.yaml")
		if err != nil {
			return err
		}

		err = replace_string_in_file("manager/ab0x_amd64.go", "func init()", "func Init()")
		if err != nil {
			return err
		}

	} else if runtime.GOARCH == "arm64" {
		err := fileb0x("manager/b0x_bpfel_arm64.yaml")
		if err != nil {
			return err
		}

		err = replace_string_in_file("manager/ab0x_arm64.go", "func init()", "func Init()")
		if err != nil {
			return err
		}
	}

	return nil
}

// Build ebpf files.
//
// This needs to only be run if the ebpf C code changes! We normally
// check the compiled EBPF module into the tree, so you do not need to
// rebuild it.
func Generate() error {
	builder := Builder{}

	return builder.Generate()
}

func Bin() error {
	builder := Builder{}
	return builder.Bin()
}

func Race() error {
	builder := Builder{}
	return builder.Race()
}

func replace_string_in_file(filename string, old string, new string) error {
	read, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	newContents := strings.Replace(string(read), old, new, -1)
	return ioutil.WriteFile(filename, []byte(newContents), 0644)
}

func fileb0x(asset string) error {
	err := sh.Run("fileb0x", asset)
	if err != nil {
		err = sh.Run(mg.GoCmd(), "install", "github.com/Velocidex/fileb0x@d54f4040016051dd9657ce04d0ae6f31eab99bc6")
		if err != nil {
			return err
		}

		err = sh.Run("fileb0x", asset)
	}

	return err
}

func SyncCode() error {
	m, err := mutations.LoadMutations("mutations/mutations.yaml")
	if err != nil {
		return err
	}

	return m.ApplyMutations()
}
