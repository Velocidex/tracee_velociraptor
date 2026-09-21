//go:build mage
// +build mage

package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Velocidex/tracee_velociraptor/mutations"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type Builder struct {
	// The object files we built
	obj      string
	go_file  string
	box_file string
	embed    string
	cmdline  []string
}

func (self Builder) generate(env map[string]string) error {
	closer, err := self.cwd("manager")
	if err != nil {
		return err
	}
	defer closer()

	err = sh.RunWith(env, mg.GoCmd(), self.cmdline...)
	if err != nil {
		return err
	}

	return os.Rename("./ebpf_bpfel.o", filepath.Base(self.obj))
}

func (self Builder) fixAssets() error {
	// Remove the go:embed so we can manage accedding the data from fileb0x.
	replace_string_in_file(self.go_file, `//go:embed `, "//")

	// Decompress the data on demand.
	replace_string_in_file(self.go_file, `bytes.NewReader(_EbpfBytes)`,
		`bytes.NewReader(getEbpfBytes())`)

	err := fileb0x(self.box_file)
	if err != nil {
		return err
	}

	// Delay initialization until we are ready.
	return replace_string_in_file(self.embed, "func init()", "func Init()")
}

var (
	arm64BuildSpec = Builder{
		obj:      "manager/ebpf_bpfel_arm64.o",
		go_file:  "manager/ebpf_bpfel.go",
		box_file: "manager/b0x_bpfel_arm64.yaml",
		embed:    "manager/ab0x_arm64.go",
		cmdline: []string{"run",
			"github.com/cilium/ebpf/cmd/bpf2go",
			"-type", "config_entry_t",
			"-type", "event_context_t",
			"-type", "event_config_t",
			"-no-global-types",
			"-target", "bpfel",
			"-go-package", "manager",
			"ebpf", "../c/tracee.bpf.c",
			"--", "-I../c/", "-D__TARGET_ARCH_arm64", "-DDEBUG_K",
		},
	}

	amd64BuildSpec = Builder{
		obj:      "manager/ebpf_bpfel_amd64.o",
		go_file:  "manager/ebpf_bpfel.go",
		box_file: "manager/b0x_bpfel_amd64.yaml",
		embed:    "manager/ab0x_amd64.go",
		cmdline: []string{"run",
			"github.com/cilium/ebpf/cmd/bpf2go",
			"-type", "config_entry_t",
			"-type", "event_context_t",
			"-type", "event_config_t",
			"-no-global-types",
			"-target", "bpfel",
			"-go-package", "manager",
			"ebpf", "../c/tracee.bpf.c",
			"--", "-I../c/", "-D__TARGET_ARCH_x86", "-DDEBUG_K",
		},
	}
)

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

func getBuilder() Builder {
	if runtime.GOARCH == "amd64" {
		return amd64BuildSpec
	} else if runtime.GOARCH == "arm64" {
		return arm64BuildSpec
	} else {
		panic("Architecture not supported!")
	}
}

func (self *Builder) Bin() error {
	return sh.RunWith(self.Env(), mg.GoCmd(), "build",
		"-o", "./ebpf_test", "./userspace/cmd/",
	)
}

func (self *Builder) Race() error {
	return sh.RunWith(self.Env(), mg.GoCmd(), "build",
		"-o", "./test", "-race",
		"./userspace/cmd/",
	)
}

func (self *Builder) Generate() error {
	err := self.generate(self.Env())
	if err != nil {
		return err
	}

	return self.fixAssets()
}

// Build ebpf files.
//
// This needs to only be run if the ebpf C code changes! We normally
// check the compiled EBPF module into the tree, so you do not need to
// rebuild it.
func Generate() error {
	builder := getBuilder()
	return builder.Generate()
}

func Bin() error {
	builder := getBuilder()
	return builder.Bin()
}

func Race() error {
	builder := getBuilder()
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
