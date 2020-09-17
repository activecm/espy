package zeek

import (
	//"bytes"
	"testing"
	"time"

	//"github.com/espy/input"
	"github.com/stretchr/testify/assert"
)

func TestGetHeader(t *testing.T) {
	currTime := time.Date(int(2020), time.May, int(5), int(12), int(21), int(58), int(21), time.UTC)

	timeStr := "2020-05-05-12-21-58"
	expectedStr := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n" +
		"#unset_field\t-\n#path\tconn\n#open\t" + timeStr +
		"\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t" +
		"proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\t" +
		"local_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\t" +
		"orig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\t" +
		"orig_network_id\tresp_network_id\torig_network_name\tresp_network_name\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t" +
		"interval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\t" +
		"count\tcount\tcount\tcount\tset[string]\tstring\tstring\tstring\tstring\n"

	resStr := getHeader(currTime)

	assert.Equal(t, expectedStr, resStr, "The header strings should be equal")
}

/*
TODO: Modify tests to use ECSSession
var sampleRecordA = &fields.OutputRecord{
	TimeFlowStart: 1640362344.21,
	SrcIP:         []byte{192, 168, 21, 44},
	DstIP:         []byte{21, 33, 45, 19},
	SrcPort:       8999,
	DstPort:       8999,
	Proto:         4,
	TimeFlowEnd:   1640362463.42,
	Packets:       348,
	Bytes:         3400000,
}

var sampleStringA = "1640362344.210000\t-\t192.168.21.44\t8999\t21.33.45.19\t8999\tIPv4\t-\t119.210000\t0\t0\t-\tF\tF\t0\t-\t348\t3400000\t0\t0\t(empty)\n"

var sampleRecordB = &fields.OutputRecord{
	TimeFlowStart: 1569065571.56,
	SrcIP:         []byte{32, 152, 18, 223},
	DstIP:         []byte{192, 21, 23, 1},
	SrcPort:       443,
	DstPort:       443,
	Proto:         55,
	TimeFlowEnd:   1569065592.15,
	Packets:       123,
	Bytes:         1200000,
}

var sampleStringB = "1569065571.560000\t-\t32.152.18.223\t443\t192.21.23.1\t443\tMOBILE\t-\t20.590000\t0\t0\t-\tF\tF\t0\t-\t123\t1200000\t0\t0\t(empty)\n"

var sampleRecordC = &fields.OutputRecord{
	TimeFlowStart: 1237378961.33,
	SrcIP:         []byte{192, 168, 21, 44},
	DstIP:         []byte{21, 33, 45, 19},
	SrcPort:       80,
	DstPort:       80,
	Proto:         4,
	TimeFlowEnd:   1237378988.15,
	Packets:       44,
	Bytes:         440000,
}

var sampleStringC = "1237378961.330000\t-\t192.168.21.44\t80\t21.33.45.19\t80\tIPv4\t-\t26.820000\t0\t0\t-\tF\tF\t0\t-\t44\t440000\t0\t0\t(empty)\n"

func TestWriteLine(t *testing.T) {
	fieldsEmpty := make([]*fields.OutputRecord, 0)
	fieldsErr := writeLine(fieldsEmpty, nil)

	fieldSingle := make([]*fields.OutputRecord, 0)
	fieldSingle = append(fieldSingle, sampleRecordA)

	fieldsMultiple := make([]*fields.OutputRecord, 0)
	fieldsMultiple = append(fieldsMultiple, sampleRecordA, sampleRecordB, sampleRecordC)

	buff := new(bytes.Buffer)

	err := writeLine(fieldSingle, buff)
	if err != nil {
		t.Error(err)
	}
	singleField := buff.String()

	buff.Reset()

	err = writeLine(fieldsMultiple, buff)
	if err != nil {
		t.Error(err)
	}

	multFields := buff.String()

	assert.Equal(t, nil, fieldsErr, "Should return nil")
	assert.Equal(t, sampleStringA, singleField, "Should be equal")
	assert.Equal(t, sampleStringA+sampleStringB+sampleStringC, multFields, "Should be equal")
}

func TestOutputRecordToString(t *testing.T) {
	fieldSingle := make([]*fields.OutputRecord, 0)
	fieldSingle = append(fieldSingle, sampleRecordB)

	outStr := outputRecordsToString(fieldSingle)

	assert.Equal(t, sampleStringB, outStr, "Should be equal")
}
*/
