package zeek

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/activecm/espy/espy/input"
	"github.com/activecm/espy/espy/util"
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
	var outputBuilder strings.Builder
	header := c.Header()
	//escape \\x09 to tab
	separator, _ := strconv.Unquote(fmt.Sprintf("\"%s\"", header.Separator))

	for i := range outputData {
		goStartTime, err := time.Parse(time.RFC3339Nano, outputData[i].RFCTimestamp)
		if err != nil {
			return output, input.ErrMalformedECSRecord
		}

		answersSetBuilder := strings.Builder{}
		answerTypeName := header.UnsetField
		answerTypeID := header.UnsetField

		// Don't report CNAME responses since Zeek doesn't
		// WEIRD: Windows issues A queries for IP addresses and gets back "-" in the answers
		shouldHandleAnswer := func(dnsType, dnsData string) bool {
			return dnsType != "CNAME" && dnsData != "-"
		}

		if len(outputData[i].DNS.Answers) > 0 {
			// We have to split out the last iteration of this loop so we don't write out a trailing comma
			for j := 0; j < len(outputData[i].DNS.Answers)-1; j++ {
				if shouldHandleAnswer(outputData[i].DNS.Answers[j].Type, outputData[i].DNS.Answers[j].Data) {
					answersSetBuilder.WriteString(outputData[i].DNS.Answers[j].Data)
					answersSetBuilder.WriteString(header.SetSeparator)
					answerTypeName = outputData[i].DNS.Answers[j].Type
				}
			}
			lastIdx := len(outputData[i].DNS.Answers) - 1
			if shouldHandleAnswer(outputData[i].DNS.Answers[lastIdx].Type, outputData[i].DNS.Answers[lastIdx].Data) {
				answersSetBuilder.WriteString(outputData[i].DNS.Answers[lastIdx].Data)
				answerTypeName = outputData[i].DNS.Answers[lastIdx].Type
			}

			tmpAnswerTypeID, err := dnsQueryTypeToID(answerTypeName)
			if err == nil {
				answerTypeID = tmpAnswerTypeID
			} // swallow error otherwise and don't set the answer type ID
		}
		if answersSetBuilder.Len() == 0 {
			answersSetBuilder.WriteString(header.EmptyField)
		}

		// from Sam: WARNING the way we handle data in RITA uses a floating time and splits
		//  on the . in a time string. As such this needs to be a floating point
		//  number. If we change the ingestion to handle floating timestamps this
		//  can be changed

		for _, sourceIP := range util.SelectPublicPrivateIPs(outputData[i].Host.IP) {
			values := []string{
				fmt.Sprintf("%.6f", float64(goStartTime.UnixNano())/1e9), // "ts"
				header.UnsetField,               // "uid"
				sourceIP,                        // "id.orig_h"
				header.UnsetField,               // "id.orig_p"
				header.UnsetField,               // "id.resp_h"
				header.UnsetField,               // "id.resp_p",
				header.UnsetField,               // "proto"
				header.UnsetField,               // "trans_id"
				header.UnsetField,               // "rtt"
				outputData[i].DNS.Question.Name, // "query"
				header.UnsetField,               // "qclass"
				header.UnsetField,               // "qclass_name",
				answerTypeID,                    // "qtype"
				answerTypeName,                  // "qtype_name"
				header.UnsetField,               // "rcode"
				header.UnsetField,               // "rcode_name"
				header.UnsetField,               // "AA"
				header.UnsetField,               // "TC"
				header.UnsetField,               // "RD"
				header.UnsetField,               // "RA"
				header.UnsetField,               // "Z",
				answersSetBuilder.String(),      // "answers"
				header.UnsetField,               // "TTLs"
				header.UnsetField,               // "rejected"
				outputData[i].Agent.Hostname,    // "agent_hostname"
				outputData[i].Agent.ID,          // "agent_uuid"
			}

			lastIdx := len(values) - 1
			for j := 0; j < lastIdx; j++ {
				outputBuilder.WriteString(values[j])
				outputBuilder.WriteString(separator)
			}
			outputBuilder.WriteString(values[lastIdx])
			outputBuilder.WriteString("\n")
		}
	}
	output = outputBuilder.String()
	return output, err
}

func (c DnsTSV) HandlesECSRecord(data input.ECSRecord) bool {
	return data.Event.Provider == "Microsoft-Windows-Sysmon" && data.Event.Code.String() == "22"
}

func init() {
	RegisteredTSVFileTypes = append(RegisteredTSVFileTypes, DnsTSV{})
}
