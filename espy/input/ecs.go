package input

import "errors"

var ErrMalformedECSRecord = errors.New("encountered malformed data in ECSRecord")

//ECSRecord is the union of Elastic comma schema fields used by *beats software
type ECSRecord struct {
	RFCTimestamp string `json:"@timestamp"`
	// Type string // Not supported by sysmon/ winlogbeat. Use with packetbeat.

	Agent struct {
		Hostname string
		ID       string
	}
	Source struct {
		IP   string
		Port int
		// Bytes   int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
		// Packets int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
	}
	Destination struct {
		IP   string
		Port int
		//		Bytes   int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
		//		Packets int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
	}
	Network struct {
		Transport string // RITA Proto
		Protocol  string // RITA Service
	}
	Event struct {
		//		Duration float64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
		Provider string
		Code     int
	}
	DNS struct {
		Answers []struct {
			Type string
			Data string
		}
		Question struct {
			Name string
		}
	}
}
