//go:build amd64

package manager

import (
	"bytes"
	"compress/gzip"
	"io/ioutil"
)

func getEbpfBytes() []byte {
	rb := bytes.NewReader(FileUserspaceEbpfEbpfBpfelAmd64O)
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
