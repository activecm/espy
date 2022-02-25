package zeek

import (
	"fmt"
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
	for _, data := range outputData {
		goStartTime, err := time.Parse(time.RFC3339Nano, data.RFCTimestamp)
		if err != nil {
			return output, input.ErrMalformedECSRecord
		}

		output += fmt.Sprintf("%.6f\t-\t%s\t%d\t%s\t%d\t%s\t%s\t-\t-\t-\t-\tF\tF\t-\t-\t-\t-\t-\t-\t(empty)\t%s\t%s\n",
			// from Sam: WARNING the way we handle data in RITA uses a floating time and splits
			//  on the . in a time string. As such this needs to be a floating point
			//  number. If we change the ingestion to handle floating timestamps this
			//  can be changed
			float64(goStartTime.UnixNano())/1e9,
			data.Source.IP,
			data.Source.Port,
			data.Destination.IP,
			data.Destination.Port,
			data.Network.Transport,
			data.Network.Protocol,
			data.Agent.ID,
			data.Agent.Hostname,
		)
	}
	return output, err
}

func (c ConnTSV) HandlesECSRecord(data input.ECSRecord) bool {
	return data.Event.Provider == "sysmon" && data.Event.Code == "3"
}

func init() {
	RegisteredTSVFileTypes = append(RegisteredTSVFileTypes, ConnTSV{})
}
