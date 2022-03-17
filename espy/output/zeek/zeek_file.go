package zeek

import (
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/activecm/espy/espy/input"
	"github.com/benbjohnson/clock"
	"github.com/spf13/afero"
)

//TSVHeader represents the header fields of a Zeek TSV document
type TSVHeader struct {
	Separator    string
	SetSeparator string
	EmptyField   string
	UnsetField   string
	Path         string
	OpenTime     time.Time
	Fields       []string
	Types        []string
}

//WithOpenTime returns a copy of the ZeekHeader with the given open_time
func (z TSVHeader) WithOpenTime(openTime time.Time) TSVHeader {
	//z is passed by value here so we can just set the field and return it
	z.OpenTime = openTime
	return z
}

//String formats the ZeekHeader as the header of a Zeek TSV document
func (z TSVHeader) String() string {
	var builder strings.Builder

	//escape \\x09 to tab
	sep, _ := strconv.Unquote(fmt.Sprintf("\"%s\"", z.Separator))

	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "separator", " ", z.Separator,
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "set_separator", sep, z.SetSeparator,
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "empty_field", sep, z.EmptyField,
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "unset_field", sep, z.UnsetField,
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "path", sep, z.Path,
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "open", sep, z.OpenTime.Format("2006-01-02-15-04-05"),
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "fields", sep, strings.Join(z.Fields, sep),
	))
	builder.WriteString(fmt.Sprintf(
		"#%s%s%s\n", "types", sep, strings.Join(z.Types, sep),
	))
	return builder.String()
}

//FormatTSVClose returns the close footer that is included at the end of each Zeek TSV file
func FormatTSVClose(header TSVHeader, closeTime time.Time) string {
	//escape \\x09 to tab
	sep, _ := strconv.Unquote(fmt.Sprintf("\"%s\"", header.Separator))
	return fmt.Sprintf("#%s%s%s\n", "close", sep, closeTime.Format("2006-01-02-15-04-05"))
}

//TSVFileType provides methods for formatting ECSRecords as Zeek TSV entries
type TSVFileType interface {
	//Header returns a ZeekHeader struct detailing the format of this Zeek TSV file type
	Header() TSVHeader
	//FormatLines formats Elastic Common Schema records as lines of this Zeek TSV file type
	FormatLines(outputData []input.ECSRecord) (output string, err error)
	//HandlesECSRecord turns true if the data in the given ECS record can be formatted as a line of this Zeek TSV file type
	HandlesECSRecord(data input.ECSRecord) bool
}

//RegisteredTSVFileTypes is initialized with the supported Zeek file types when the zeek package is imported
//See conn.go and dns.go.
var RegisteredTSVFileTypes []TSVFileType

//MapECSRecordsToTSVFiles maps the given Elastic Common Schema records to the Zeek files that
//they should be written to
func MapECSRecordsToTSVFiles(ecsRecords []input.ECSRecord) map[TSVFileType][]input.ECSRecord {
	outputMap := make(map[TSVFileType][]input.ECSRecord)
	for i := range ecsRecords {
		for j := range RegisteredTSVFileTypes {
			if RegisteredTSVFileTypes[j].HandlesECSRecord(ecsRecords[i]) {
				outputMap[RegisteredTSVFileTypes[j]] = append(outputMap[RegisteredTSVFileTypes[j]], ecsRecords[i])
			}
		}
	}
	return outputMap
}

//WriteTSVHeader writes out the header for a newly opened Zeek TSV file of the given type
func WriteTSVHeader(fileType TSVFileType, openTime time.Time, fileWriter io.Writer) error {
	fileHeader := fileType.Header().WithOpenTime(openTime).String()
	if _, err := fileWriter.Write([]byte(fileHeader)); err != nil {
		return err
	}
	return nil
}

//WriteTSVLines writes out Elastic Common Schema records as lines of the given Zeek TSV file type to the given writer
func WriteTSVLines(fileType TSVFileType, outputData []input.ECSRecord, fileWriter io.Writer) error {
	if len(outputData) == 0 {
		return nil
	}

	writeString, err := fileType.FormatLines(outputData)
	if err != nil {
		return err
	}

	if _, err := fileWriter.Write([]byte(writeString)); err != nil {
		return err
	}

	return nil
}

//WriteTSVFooter writes out the footer for a Zeek TSV file of the given type
func WriteTSVFooter(fileType TSVFileType, closeTime time.Time, fileWriter io.Writer) error {
	header := fileType.Header()

	fileClose := FormatTSVClose(header, closeTime)
	if _, err := fileWriter.Write([]byte(fileClose)); err != nil {
		return err
	}
	return nil
}

//OpenTSVFile opens a Zeek TSV file at the given file path. If the file does not exist,
//this function creates the file and writes out the appropriate Zeek TSV header as described
//by the given Zeek file type.
func OpenTSVFile(fs afero.Fs, clock clock.Clock, fileType TSVFileType, filePath string) (file afero.File, err error) {
	directory := path.Dir(filePath)
	err = fs.MkdirAll(directory, 0755)
	if err != nil {
		return nil, err
	}

	file, err = fs.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err == nil {
		err = WriteTSVHeader(fileType, clock.Now(), file)
		if err != nil {
			return nil, err
		}
	} else if os.IsExist(err) {
		file, err = fs.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return file, nil
}
