//go:build !cgo

package passive

import (
	"errors"
	"time"

	"discovr/internal/types"
)

func ListInterfaces() ([]Interface, error) {
	return nil, errors.New("passive discovery requires cgo/libpcap support")
}

type Config struct {
	Iface   string
	Timeout time.Duration
}

func Discover(cfg Config) ([]types.Asset, int, error) {
	return nil, 0, errors.New("passive discovery unavailable: built without cgo")
}
