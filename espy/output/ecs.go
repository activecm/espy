package output

import (
	"github.com/activecm/espy/espy/input"
)

// ECSWriter writes out deserialized Elastic Common Schema records
type ECSWriter interface {
	//WriteECSRecords writes out deserialized ECS records
	WriteECSRecords(outputData []input.ECSRecord) error
	//Close frees any resources held by this writer
	Close() error
}
