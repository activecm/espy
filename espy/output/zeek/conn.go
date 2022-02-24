package zeek

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/activecm/espy/espy/input"
)

var ErrMalformedECSSession = errors.New("encountered malformed data in ECSSession")

func newConnHeader(headerTime time.Time) ZeekHeader {
	return ZeekHeader{
		Separator:    "\\x09",
		SetSeparator: ",",
		EmptyField:   "(empty)",
		UnsetField:   "-",
		Path:         "conn",
		OpenTime:     headerTime,
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

func writeConnLines(outputData []*input.ECSRecord, fileWriter io.Writer) error {
	if len(outputData) == 0 {
		return nil
	}

	writeString, err := formatECSAsConnTSV(outputData)
	if err != nil {
		return err
	}

	if _, err := fileWriter.Write([]byte(writeString)); err != nil {
		return err
	}

	return nil
}

func formatECSAsConnTSV(outputData []*input.ECSRecord) (output string, err error) {
	for _, data := range outputData {
		goStartTime, err := time.Parse(time.RFC3339Nano, data.RFCTimestamp)
		if err != nil {
			return output, ErrMalformedECSSession
		}

		output += fmt.Sprintf("%.6f\t-\t%s\t%d\t%s\t%d\t%s\t-\t-\t-\t-\t-\tF\tF\t-\t-\t-\t-\t-\t-\t(empty)\t%s\t%s\n",
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
			data.Agent.ID,
			data.Agent.Hostname,
		)
	}
	return output, err
}

// initConnSpoolFile will create and setup our spool directory
// for buffering incoming connection logs
func initConnSpoolFile(spoolFile, spoolDir string) (file *os.File, err error) {
	err = os.MkdirAll(spoolDir, 0755)
	if err != nil {
		return nil, err
	}

	file, err = os.OpenFile(spoolFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)

	if err == nil {
		fileHeader := newConnHeader(time.Now()).String()
		if _, err = file.Write([]byte(fileHeader)); err != nil {
			return nil, err
		}
	} else if os.IsExist(err) {
		file, err = os.OpenFile(spoolFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	return file, nil
}
