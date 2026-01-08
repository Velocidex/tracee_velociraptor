package container

import "errors"

type Manager struct{}

func (self Manager) FindContainerCgroupID32LSB(in string) ([]uint64, error) {
	return nil, errors.New("Not implemented")
}
