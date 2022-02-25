package zeek

// func TestGetOutputFileName(t *testing.T) {
// 	var testStr string
// 	currTime := time.Date(int(2020), time.April, int(20), int(16), int(20), int(0), int(0), time.UTC)

// 	w, err := CreateRollingWritingSystem("/opt/zeek/logs", func() {})
// 	if err != nil {
// 		t.Error(err)
// 	}

// 	timeStr := "/opt/zeek/logs/2020-04-20/conn.15:00:00-16:00:00.log.gz"

// 	testWr, ok := w.(*RollingWriter)

// 	if !ok {
// 		t.Error("Failed to cast system to writer object")
// 	}

// 	testWr.archiveDir = "/opt/zeek/logs"
// 	testStr = testWr.getArchivePath(ConnTSVFile{}.Header().Path, currTime)

// 	assert.Equal(t, timeStr, testStr, "The file paths should be equal")
// }

/*
func TestClose(t *testing.T) {
	w, err := CreateRollingWritingSystem("/opt/zeek/logs", false)
	if err != nil {
		t.Error(err)
	}

	tstWr, ok := w.(*RollingWriter)

	if !ok {
		t.Error("Failed to cast system to writer object")
	}

	tstWr.Close
	err = tstWr.Close()
	if err != nil {
		t.Error("Error with closing: " + err.Error())
	}

	assert.Equal(t, err, nil, "Closing should return no errors")
}*/

/*
func TestWriteECSRecords(t *testing.T) {
	w, err := CreateRollingWritingSystem("/opt/zeek/logs", false)
	if err != nil {
		t.Error(err)
	}
	testWr, ok := w.(*RollingWriter)
	if !ok {
		t.Error("Failed to cast writer.System to RollingSystem for some reason")
	}

	emptyData := make([]*fields.OutputRecord, 3)

	err = testWr.WriteECSRecords(emptyData)

	assert.Equal(t, err, nil, "Should return with no errors")
}
*/
