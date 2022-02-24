package zeek

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/activecm/espy/espy/input"
)

var ErrMalformedECSSession = errors.New("Encountered malformed data in ECSSession")

func getConnHeader(headerTime time.Time) string {
	return "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n" +
		"#unset_field\t-\n#path\tconn\n#open\t" + headerTime.Format("2006-01-02-15-04-05") +
		"\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t" +
		"proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\t" +
		"local_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\t" +
		"orig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\t" +
		"agent_uuid\tagent_hostname\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t" +
		"interval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\t" +
		"count\tcount\tcount\tcount\tset[string]\tstring\tstring\n"
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
		fileHeader := getConnHeader(time.Now())
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
