package output

import "github.com/activecm/BeaKer/espy/input"

type ECSWriter interface {
	AddSessionToWriter(outputData []*input.ECSSession) error
	Close() error
}
