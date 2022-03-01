package zeek

import (
	"fmt"
	"strings"
	"time"

	"github.com/activecm/espy/espy/input"
)

func dnsQueryTypeToID(qType string) (string, error) {
	//definitions based on https://github.com/miekg/dns/blob/master/types.go
	dnsMap := map[string]string{
		"A":          "1",
		"NS":         "2",
		"MD":         "3",
		"MF":         "4",
		"CNAME":      "5",
		"SOA":        "6",
		"MB":         "7",
		"MG":         "8",
		"MR":         "9",
		"NULL":       "10",
		"PTR":        "12",
		"HINFO":      "13",
		"MINFO":      "14",
		"MX":         "15",
		"TXT":        "16",
		"RP":         "17",
		"AFSDB":      "18",
		"X25":        "19",
		"ISDN":       "20",
		"RT":         "21",
		"NSAPPTR":    "23",
		"SIG":        "24",
		"KEY":        "25",
		"PX":         "26",
		"GPOS":       "27",
		"AAAA":       "28",
		"LOC":        "29",
		"NXT":        "30",
		"EID":        "31",
		"NIMLOC":     "32",
		"SRV":        "33",
		"ATMA":       "34",
		"NAPTR":      "35",
		"KX":         "36",
		"CERT":       "37",
		"DNAME":      "39",
		"OPT":        "41",
		"APL":        "42",
		"DS":         "43",
		"SSHFP":      "44",
		"RRSIG":      "46",
		"NSEC":       "47",
		"DNSKEY":     "48",
		"DHCID":      "49",
		"NSEC3":      "50",
		"NSEC3PARAM": "51",
		"TLSA":       "52",
		"SMIMEA":     "53",
		"HIP":        "55",
		"NINFO":      "56",
		"RKEY":       "57",
		"TALINK":     "58",
		"CDS":        "59",
		"CDNSKEY":    "60",
		"OPENPGPKEY": "61",
		"CSYNC":      "62",
		"ZONEMD":     "63",
		"SVCB":       "64",
		"HTTPS":      "65",
		"SPF":        "99",
		"UINFO":      "100",
		"UID":        "101",
		"GID":        "102",
		"UNSPEC":     "103",
		"NID":        "104",
		"L32":        "105",
		"L64":        "106",
		"LP":         "107",
		"EUI48":      "108",
		"EUI64":      "109",
		"URI":        "256",
		"CAA":        "257",
		"AVC":        "258",
	}
	qTypeID, ok := dnsMap[qType]
	if !ok {
		return "", fmt.Errorf("invalid DNS type: %s", qType)
	}
	return qTypeID, nil
}

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
		answerType := c.Header().UnsetField
		answerTypeName := c.Header().UnsetField
		if len(outputData[i].DNS.Answers) > 0 {
			for j := 0; j < len(outputData[i].DNS.Answers)-1; j++ {
				answersSetBuilder.WriteString(outputData[i].DNS.Answers[j].Data)
				answersSetBuilder.WriteString(c.Header().SetSeparator)
			}
			answersSetBuilder.WriteString(outputData[i].DNS.Answers[len(outputData[i].DNS.Answers)-1].Data)
			answerType = outputData[i].DNS.Answers[0].Type
			tmpAnswerTypeName, err := dnsQueryTypeToID(answerType)
			if err == nil {
				answerTypeName = tmpAnswerTypeName
			} // swallow error otherwise and don't set the answer type name
		}

		output += fmt.Sprintf(
			"%.6f\t-\t%s\t%d\t%s\t%d\t%s\t-\t-\t%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t%s\t(empty)\t-\t%s\t%s\n",
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
			answerType,
			answerTypeName,
			answersSetBuilder.String(),
			outputData[i].Agent.Hostname,
			outputData[i].Agent.ID,
		)
	}
	return output, err
}

func (c DnsTSV) HandlesECSRecord(data input.ECSRecord) bool {
	return data.Event.Provider == "sysmon" && data.Event.Code == 22
}

func init() {
	RegisteredTSVFileTypes = append(RegisteredTSVFileTypes, DnsTSV{})
}
