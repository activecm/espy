package zeek

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstructor(t *testing.T) {
	w, err := CreateStandardWritingSystem("/opt/zeek/logs")
	if err != nil {
		t.Error(err)
	}

	tstWr, ok := w.(*StandardWriter)
	if !ok {
		t.Error("System failed to cast to Standard Writer")
	}

	assert.Equal(t, tstWr.spoolFile, "/opt/zeek/logs/flow-spool/conn.log", "The strings should be equal")
	assert.Equal(t, tstWr.outFileName, "/opt/zeek/logs/conn.log.gz", "The strings should be equal")
}

func TestClosing(t *testing.T) {
	w, err := CreateStandardWritingSystem("/opt/zeek/logs")
	if err != nil {
		t.Error(err)
	}

	tstWr, ok := w.(*StandardWriter)
	if !ok {
		t.Error("System failed to cast to Standard Writer")
	}

	err = tstWr.Close()

	assert.Equal(t, err, nil, "Closing should return no errors")
}
