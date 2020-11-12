package output

import "github.com/activecm/espy/espy/input"

type ECSWriter interface {
	AddSessionToWriter(outputData []*input.ECSSession) error
	Close() error
}
