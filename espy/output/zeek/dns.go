package zeek

import (
	"fmt"
	"strings"
	"time"

	"github.com/activecm/espy/espy/input"
)

type DnsTSV struct{}

func (c DnsTSV) Header() TSVHeader {
	return TSVHeader{
		Separator:    "\\x09",
		SetSeparator: ",",
		EmptyField:   "(empty)",
		UnsetField:   "-",
		Path:         "dns",
		Fields: []string{
			"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
			"proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
			"qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z",
			"answers", "TTLs", "rejected", "agent_hostname", "agent_uuid",
		},
		Types: []string{
			"time", "string", "addr", "port", "addr", "port", "enum", "count",
			"interval", "string", "count", "string", "count", "string", "count", "string",
			"bool", "bool", "bool", "bool", "count", "vector[string]", "vector[interval]",
			"bool", "string", "string",
		},
	}
}

func (c DnsTSV) FormatLines(outputData []input.ECSRecord) (output string, err error) {
	for i := range outputData {
		goStartTime, err := time.Parse(time.RFC3339Nano, outputData[i].RFCTimestamp)
		if err != nil {
			return output, input.ErrMalformedECSRecord
		}

		answersSetBuilder := strings.Builder{}
		if len(outputData[i].DNS.Answers) > 0 {
			for j := 0; j < len(outputData[i].DNS.Answers)-1; j++ {
				answersSetBuilder.WriteString(outputData[i].DNS.Answers[j].Data)
				answersSetBuilder.WriteString(c.Header().SetSeparator)
			}
			answersSetBuilder.WriteString(outputData[i].DNS.Answers[len(outputData[i].DNS.Answers)-1].Data)
		}

		output += fmt.Sprintf(
			"%.6f\t-\t%s\t%d\t%s\t%d\t%s\t-\t-\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t%s\t(empty)\t-\t%s\t%s\n",
			// from Sam: WARNING the way we handle data in RITA uses a floating time and splits
			//  on the . in a time string. As such this needs to be a floating point
			//  number. If we change the ingestion to handle floating timestamps this
			//  can be changed
			float64(goStartTime.UnixNano())/1e9,
			outputData[i].Source.IP,
			outputData[i].Source.Port,
			outputData[i].Destination.IP,
			outputData[i].Destination.Port,
			outputData[i].Network.Transport,
			outputData[i].DNS.Question.Name,
			answersSetBuilder.String(),
			outputData[i].Agent.Hostname,
			outputData[i].Agent.ID,
		)
	}
	return output, err
}

func (c DnsTSV) HandlesECSRecord(data input.ECSRecord) bool {
	return data.Event.Provider == "sysmon" && data.Event.Code == "22"
}

func init() {
	RegisteredTSVFileTypes = append(RegisteredTSVFileTypes, DnsTSV{})
}
