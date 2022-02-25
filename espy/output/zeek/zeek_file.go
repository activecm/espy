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
)

//ZeekHeader represents the header fields of a Zeek TSV document
type ZeekHeader struct {
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
func (z ZeekHeader) WithOpenTime(openTime time.Time) ZeekHeader {
	//z is passed by value here so we can just set the field and return it
	z.OpenTime = openTime
	return z
}

//String formats the ZeekHeader as the header of a Zeek TSV document
func (z ZeekHeader) String() string {
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

//FormatZeekTSVClose returns the close footer that is included at the end of each Zeek TSV file
func FormatZeekTSVClose(header ZeekHeader, closeTime time.Time) string {
	//escape \\x09 to tab
	sep, _ := strconv.Unquote(fmt.Sprintf("\"%s\"", header.Separator))
	return fmt.Sprintf("#%s%s%s\n", "close", sep, closeTime.Format("2006-01-02-15-04-05"))
}

//ZeekTSVFile provides methods for formatting ECSRecords as Zeek TSV entries
type ZeekTSVFile interface {
	//Header returns a ZeekHeader struct detailing the format of this Zeek TSV file type
	Header() ZeekHeader
	//FormatLines formats Elastic Common Schema records as lines of this Zeek TSV file type
	FormatLines(outputData []*input.ECSRecord) (output string, err error)
}

//WriteTSVHeader writes out the header for a newly opened Zeek TSV file of the given type
func WriteTSVHeader(fileType ZeekTSVFile, fileWriter io.Writer) error {
	fileHeader := fileType.Header().WithOpenTime(time.Now()).String()
	if _, err := fileWriter.Write([]byte(fileHeader)); err != nil {
		return err
	}
	return nil
}

//WriteTSVLines writes out Elastic Common Schema records as lines of the given Zeek TSV file type to the given writer
func WriteTSVLines(fileType ZeekTSVFile, outputData []*input.ECSRecord, fileWriter io.Writer) error {
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
func WriteTSVFooter(fileType ZeekTSVFile, closeTime time.Time, fileWriter io.Writer) error {
	header := fileType.Header()

	fileClose := FormatZeekTSVClose(header, closeTime)
	if _, err := fileWriter.Write([]byte(fileClose)); err != nil {
		return err
	}
	return nil
}

//OpenTSVFile opens a Zeek TSV file at the given file path. If the file does not exist,
//this function creates the file and writes out the appropriate Zeek TSV header as described
//by the given Zeek file type.
func OpenTSVFile(fileType ZeekTSVFile, filePath string) (file *os.File, err error) {
	directory := path.Dir(filePath)
	err = os.MkdirAll(directory, 0755)
	if err != nil {
		return nil, err
	}

	file, err = os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err == nil {
		err = WriteTSVHeader(fileType, file)
		if err != nil {
			return nil, err
		}
	} else if os.IsExist(err) {
		file, err = os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	return file, nil
}
