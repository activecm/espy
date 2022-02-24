package zeek

import (
	"fmt"
	"strconv"
	"strings"
	"time"
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
