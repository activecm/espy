package output

// JSONWriter writes a log entry in raw json format to a destination
type JSONWriter interface {
	AddSessionToWriter(outputData string) error
	Close() error
}
