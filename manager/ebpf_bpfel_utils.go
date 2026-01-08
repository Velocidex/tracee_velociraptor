//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package manager

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
)

func getEbpfBytes() []byte {
	rb := bytes.NewReader(FileUserspaceEbpfEbpfBpfelO)
	r, err := gzip.NewReader(rb)
	if err != nil {
		panic(err)
	}

	err = r.Close()
	if err != nil {
		panic(err)
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}

	return data
}
