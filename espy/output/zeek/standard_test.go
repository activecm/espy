package zeek

import (
	"path"
	"testing"

	"github.com/benbjohnson/clock"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestOpenStandardFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	clock := clock.NewMock()
	_, err := CreateStandardWritingSystem(fs, clock, "/opt/zeek/logs")
	require.Nil(t, err, "Should be able to open spool files")
	for _, zeekFileType := range RegisteredTSVFileTypes {
		zeekPath := zeekFileType.Header().Path
		spoolPath := path.Join("/opt/zeek/logs", "ecs-spool", zeekPath+".log")
		testVal, testErr := afero.Exists(fs, spoolPath)
		require.Nil(t, testErr, "Spool file for "+zeekPath+" log should exist")
		require.True(t, testVal, "Spool file for "+zeekPath+" log should exist")
	}
}

func TestCloseStandardFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	clock := clock.NewMock()
	w, err := CreateStandardWritingSystem(fs, clock, "/opt/zeek/logs")
	require.Nil(t, err, "Should be able to open spool files")
	w.Close()
	require.Nil(t, err, "Should be able to close spool files and open archive files")
	for _, zeekFileType := range RegisteredTSVFileTypes {
		zeekPath := zeekFileType.Header().Path
		archivePath := path.Join("/opt/zeek/logs", zeekPath+".log.gz")
		testVal, testErr := afero.Exists(fs, archivePath)
		require.Nil(t, testErr, "Archive file for "+zeekPath+" log should exist")
		require.True(t, testVal, "Archive file for "+zeekPath+" log should exist")
	}
}
