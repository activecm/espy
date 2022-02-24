package output

import "github.com/activecm/espy/espy/input"

type ECSWriter interface {
	WriteECSRecords(outputData []*input.ECSRecord) error
	Close() error
}
