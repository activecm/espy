package zeek

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/activecm/espy/espy/input"
)

type ConnTSV struct{}

func (c ConnTSV) Header() TSVHeader {
	return TSVHeader{
		Separator:    "\\x09",
		SetSeparator: ",",
		EmptyField:   "(empty)",
		UnsetField:   "-",
		Path:         "conn",
		Fields: []string{
			"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
			"proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
			"local_orig", "local_resp", "missed_bytes", "history", "orig_pkts",
			"orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
			"agent_uuid", "agent_hostname",
		},
		Types: []string{
			"time", "string", "addr", "port", "addr", "port", "enum", "string",
			"interval", "count", "count", "string", "bool", "bool", "count", "string",
			"count", "count", "count", "count", "set[string]", "string", "string",
		},
	}
}

func (c ConnTSV) FormatLines(outputData []input.ECSRecord) (output string, err error) {
	var outputBuilder strings.Builder
	header := c.Header()
	//escape \\x09 to tab
	separator, _ := strconv.Unquote(fmt.Sprintf("\"%s\"", header.Separator))

	for i := range outputData {
		goStartTime, err := time.Parse(time.RFC3339Nano, outputData[i].RFCTimestamp)
		if err != nil {
			return output, input.ErrMalformedECSRecord
		}

		// from Sam: WARNING the way we handle data in RITA uses a floating time and splits
		//  on the . in a time string. As such this needs to be a floating point
		//  number. If we change the ingestion to handle floating timestamps this
		//  can be changed

		values := []string{
			fmt.Sprintf("%.6f", float64(goStartTime.UnixNano())/1e9), // "ts"
			header.UnsetField,                       // "uid"
			outputData[i].Source.IP,                 // "id.orig_h"
			outputData[i].Source.Port.String(),      // "id.orig_p"
			outputData[i].Destination.IP,            // "id.resp_h"
			outputData[i].Destination.Port.String(), // "id.resp_p",
			outputData[i].Network.Transport,         // "proto"
			outputData[i].Network.Protocol,          // "service"
			header.UnsetField,                       // "duration"
			header.UnsetField,                       // "orig_bytes"
			header.UnsetField,                       // "resp_bytes"
			header.UnsetField,                       // "conn_state",
			"F",                                     // "local_orig"
			"F",                                     // "local_resp"
			header.UnsetField,                       // "missed_bytes"
			header.UnsetField,                       // "history"
			header.UnsetField,                       // "orig_pkts",
			header.UnsetField,                       // "orig_ip_bytes"
			header.UnsetField,                       // "resp_pkts"
			header.UnsetField,                       // "resp_ip_bytes"
			header.EmptyField,                       // "tunnel_parents",
			outputData[i].Agent.ID,                  // "agent_uuid"
			outputData[i].Agent.Hostname,            // "agent_hostname",
		}

		lastIdx := len(values) - 1
		for j := 0; j < lastIdx; j++ {
			outputBuilder.WriteString(values[j])
			outputBuilder.WriteString(separator)
		}
		outputBuilder.WriteString(values[lastIdx])
		outputBuilder.WriteString("\n")
	}
	output = outputBuilder.String()
	return output, err
}

func (c ConnTSV) HandlesECSRecord(data input.ECSRecord) bool {
	return data.Event.Provider == "Microsoft-Windows-Sysmon" && data.Event.Code.String() == "3"
}

func init() {
	RegisteredTSVFileTypes = append(RegisteredTSVFileTypes, ConnTSV{})
}
