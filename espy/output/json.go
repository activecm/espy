package output

// JSONWriter writes a log entry in raw json format to a destination
type JSONWriter interface {
	//WriteECSRecords writes out JSON formatted ECS records
	WriteECSRecords(outputData []string) error
	//Close frees any resources held by this writer
	Close() error
}
