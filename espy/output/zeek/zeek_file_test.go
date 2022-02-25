package zeek

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZeekHeaderString(t *testing.T) {

	header := ConnTSV{}.Header().WithOpenTime(time.Date(2021, 02, 14, 16, 17, 18, 0, time.UTC))
	testVal := header.String()
	trueVal := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n" +
		"#unset_field\t-\n#path\tconn\n#open\t" + "2021-02-14-16-17-18" +
		"\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t" +
		"proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\t" +
		"local_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\t" +
		"orig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\t" +
		"agent_uuid\tagent_hostname\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t" +
		"interval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\t" +
		"count\tcount\tcount\tcount\tset[string]\tstring\tstring\n"

	require.Equal(t, trueVal, testVal, "Conn Zeek header is not properly formatted")
}
