package zeek

import (
	"path"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestOpenRollingFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	clock := clock.NewMock()
	clock.Set(time.Date(2022, 02, 14, 16, 17, 18, 0, time.UTC))
	_, err := CreateRollingWritingSystem(fs, clock, "/opt/zeek/logs", func() {})
	require.Nil(t, err, "Should be able to open spool files")
	for _, zeekFileType := range RegisteredTSVFileTypes {
		zeekPath := zeekFileType.Header().Path
		spoolPath := path.Join("/opt/zeek/logs", "ecs-spool", zeekPath+".log")
		testVal, testErr := afero.Exists(fs, spoolPath)
		require.Nil(t, testErr, "Spool file for "+zeekPath+" log should exist")
		require.True(t, testVal, "Spool file for "+zeekPath+" log should exist")
	}
}

func TestCloseRollingFiles(t *testing.T) {
	fs := afero.NewMemMapFs()
	clock := clock.NewMock()
	clock.Set(time.Date(2022, 02, 14, 16, 17, 18, 0, time.UTC))
	w, err := CreateRollingWritingSystem(fs, clock, "/opt/zeek/logs", func() {})
	require.Nil(t, err, "Should be able to open spool files")
	clock.Set(time.Date(2022, 02, 14, 17, 17, 18, 0, time.UTC))
	w.Close()
	require.Nil(t, err, "Should be able to close spool files and open archive files")
	for _, zeekFileType := range RegisteredTSVFileTypes {
		zeekPath := zeekFileType.Header().Path
		archivePath := path.Join("/opt/zeek/logs/2022-02-14", zeekPath+".16:00:00-17:00:00.log.gz")

		testVal, testErr := afero.Exists(fs, archivePath)
		require.Nil(t, testErr, "Archive file for "+zeekPath+" log should exist")
		require.True(t, testVal, "Archive file for "+zeekPath+" log should exist")
	}
}
