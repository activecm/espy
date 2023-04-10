package input

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

var ErrMalformedECSRecord = errors.New("encountered malformed data in ECSRecord")

type Metadata struct {
	Version string `json:"version"`
}

type ECSMetadata struct {
	Metadata Metadata `json:"@metadata"`
}

type Answer struct {
	Type string
	Data string
}

// ECSRecord is the union of Elastic comma schema fields used by *beats software
type ECSRecord struct {
	RFCTimestamp string `json:"@timestamp"`
	// Type string // Not supported by sysmon/ winlogbeat. Use with packetbeat.

	Agent struct {
		Hostname string
		ID       string
	}
	Host struct {
		IP []string
	}
	Source struct {
		IP   string
		Port json.Number
		// Bytes   int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
		// Packets int64 // Not supported by sysmon/ winlogbeat. Use with packetbeat.
	}
	Destination struct {
		IP   string
		Port json.Number
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
		Code     json.Number
	}
	DNS struct {
		Answers  []Answer
		Question struct {
			Name string
		}
	}
}

type EventDatav8 struct {
	SourceIp            string
	SourcePort          string
	DestinationIp       string
	DestinationPort     string
	Protocol            string // ECS Transport, RITA Proto
	DestinationPortName string // ECS Protocol, RITA Service
	QueryName           string
	QueryResults        string
	UtcTime             string
}

type ECSRecordv8 struct {
	RFCTimestamp string `json:"@timestamp"`
	// Type string // Not supported by sysmon/ winlogbeat. Use with packetbeat.

	Agent struct {
		Name string
		ID   string
	}

	Host struct {
		IP []string
	}

	Winlog struct {
		EventData EventDatav8 `json:"event_data"`
	}

	Event struct {
		Provider string
		Code     string
	}
}

// Processes a v8.x event log and converts it into an ECSRecord
func (r *ECSRecordv8) Process() (*ECSRecord, error) {
	newRecord := &ECSRecord{
		Host: r.Host,
	}
	// Timestamp
	// Attempt to parse UtcTime in its expected format and replace @timestamp with it
	utcTime, err := time.Parse("2006-01-02 15:04:05.999", r.Winlog.EventData.UtcTime)
	if err != nil {
		newRecord.RFCTimestamp = r.RFCTimestamp
	} else {
		newRecord.RFCTimestamp = utcTime.Format(time.RFC3339Nano)
	}

	// Agent
	newRecord.Agent.Hostname = r.Agent.Name
	newRecord.Agent.ID = r.Agent.ID

	// Source
	newRecord.Source.IP = r.Winlog.EventData.SourceIp
	if r.Winlog.EventData.SourcePort != "" && r.Winlog.EventData.SourcePort != "-" {
		srcPort, err := strconv.Atoi(r.Winlog.EventData.SourcePort)
		if err != nil {
			log.WithError(err).WithField("EventData Source Port", r.Winlog.EventData.SourcePort).Error(err.Error())
		} else {
			newRecord.Source.Port = json.Number(fmt.Sprint(srcPort))
		}
	}

	// Destination
	newRecord.Destination.IP = r.Winlog.EventData.DestinationIp
	if r.Winlog.EventData.DestinationPort != "" && r.Winlog.EventData.DestinationPort != "-" {
		dstPort, err := strconv.Atoi(r.Winlog.EventData.DestinationPort)
		if err != nil {
			log.WithError(err).WithField("EventData Destination Port", r.Winlog.EventData.DestinationPort).Error(err.Error())
		} else {
			newRecord.Destination.Port = json.Number(fmt.Sprint(dstPort))
		}
	}

	// Network
	newRecord.Network.Transport = r.Winlog.EventData.Protocol
	newRecord.Network.Protocol = r.Winlog.EventData.DestinationPortName

	// Event
	evtCode, err := strconv.Atoi(r.Event.Code)
	if err != nil {
		return nil, errors.New(err.Error() + " " + r.Event.Code)
	}
	if evtCode == 22 {
		newRecord.Network.Protocol = "dns"
	}
	newRecord.Event.Code = json.Number(fmt.Sprint(evtCode))
	newRecord.Event.Provider = r.Event.Provider

	// DNS
	newRecord.DNS.Question.Name = r.Winlog.EventData.QueryName
	newRecord.DNS.Answers = parseDNSAnswers(r.Winlog.EventData.QueryResults)

	return newRecord, nil
}

// Parses the DNS answers from the QueryResults string
func parseDNSAnswers(rawData string) []Answer {
	var answers []Answer
	if rawData == "" {
		return answers
	}

	// rawAnswers := "type:  5 a-ring.a-9999.a-msedge.net;type:  5 a-9999.a-msedge.net;::ffff:204.79.197.254;"
	rawAnswers := strings.Split(rawData, ";")
	for _, ans := range rawAnswers {
		if len(ans) > 0 {
			answerType := ""
			answerData := ans
			hasType := strings.HasPrefix(ans, "type:")
			if hasType {
				answerGroup := strings.Fields(ans)
				// If the entry starts with type:, then there should be 3 groups separated by whitespace
				if len(answerGroup) != 3 {
					continue
				}
				answerType = getDNSRecordTypes(answerGroup[1])
				answerData = answerGroup[2]

				answer := Answer{
					Type: answerType,
					Data: answerData,
				}

				answers = append(answers, answer)

			} else {
				// if there is no type, then treat it as an IP address
				answerData = strings.Replace(ans, "::ffff:", "", 1)
				if net.ParseIP(answerData) != nil {
					answerType = "A"
					if strings.Contains(answerData, ":") {
						answerType = "AAAA"
					}

					answer := Answer{
						Type: answerType,
						Data: answerData,
					}
					answers = append(answers, answer)
				}
			}
		}
	}
	return answers
}

func getDNSRecordTypes(dtype string) string {
	dnsRecordTypes := map[string]string{
		"1":     "A",
		"2":     "NS",
		"3":     "MD",
		"4":     "MF",
		"5":     "CNAME",
		"6":     "SOA",
		"7":     "MB",
		"8":     "MG",
		"9":     "MR",
		"10":    "NULL",
		"11":    "WKS",
		"12":    "PTR",
		"13":    "HINFO",
		"14":    "MINFO",
		"15":    "MX",
		"16":    "TXT",
		"17":    "RP",
		"18":    "AFSDB",
		"19":    "X25",
		"20":    "ISDN",
		"21":    "RT",
		"22":    "NSAP",
		"23":    "NSAPPTR",
		"24":    "SIG",
		"25":    "KEY",
		"26":    "PX",
		"27":    "GPOS",
		"28":    "AAAA",
		"29":    "LOC",
		"30":    "NXT",
		"31":    "EID",
		"32":    "NIMLOC",
		"33":    "SRV",
		"34":    "ATMA",
		"35":    "NAPTR",
		"36":    "KX",
		"37":    "CERT",
		"38":    "A6",
		"39":    "DNAME",
		"40":    "SINK",
		"41":    "OPT",
		"43":    "DS",
		"46":    "RRSIG",
		"47":    "NSEC",
		"48":    "DNSKEY",
		"49":    "DHCID",
		"100":   "UINFO",
		"101":   "UID",
		"102":   "GID",
		"103":   "UNSPEC",
		"248":   "ADDRS",
		"249":   "TKEY",
		"250":   "TSIG",
		"251":   "IXFR",
		"252":   "AXFR",
		"253":   "MAILB",
		"254":   "MAILA",
		"255":   "ANY",
		"65281": "WINS",
		"65282": "WINSR",
	}
	recordType, ok := dnsRecordTypes[dtype]
	if ok {
		return recordType
	}
	return ""
}
