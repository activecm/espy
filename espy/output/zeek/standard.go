package zeek

import (
	"compress/gzip"
	"fmt"
	"io"
	"path"

	"github.com/benbjohnson/clock"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"

	"github.com/activecm/espy/espy/input"
	"github.com/activecm/espy/espy/output"
)

// No scheduling, single dump file

// StandardWriter is our standard, single output
// file, will first write everything to single
// spool then move them to an appropriate, time
// stamped log file
type StandardWriter struct {
	archiveDir string
	spoolDir   string

	fs         afero.Fs
	clock      clock.Clock
	spoolFiles map[TSVFileType]afero.File
}

// CreateStandardWritingSystem Creates a single shot writer system
func CreateStandardWritingSystem(fs afero.Fs, clock clock.Clock, tgtDir string) (output.ECSWriter, error) {
	var err error
	w := &StandardWriter{
		fs:         fs,
		clock:      clock,
		archiveDir: tgtDir,
		spoolDir:   path.Join(tgtDir, "/ecs-spool"),
		spoolFiles: make(map[TSVFileType]afero.File, len(RegisteredTSVFileTypes)),
	}

	for i := range RegisteredTSVFileTypes {
		fileName := fmt.Sprintf("%s.log", RegisteredTSVFileTypes[i].Header().Path)
		filePath := path.Join(w.spoolDir, fileName)
		w.spoolFiles[RegisteredTSVFileTypes[i]], err = OpenTSVFile(fs, clock, RegisteredTSVFileTypes[i], filePath)
		if err != nil {
			return nil, err
		}
	}
	log.Info("Initialized standard file writer")
	return w, nil
}

// WriteECSRecords writes Elastic Common Schema records out to Zeek files
func (w *StandardWriter) WriteECSRecords(outputData []input.ECSRecord) error {
	log.Debugf("Writing %d records", len(outputData))

	for zeekFileType, groupedData := range MapECSRecordsToTSVFiles(outputData) {
		err := WriteTSVLines(zeekFileType, groupedData, w.spoolFiles[zeekFileType])
		if err != nil {
			return err
		}
	}

	return nil
}

// Close will close all open sessions and rotate everything
// from spool data to logs
func (w *StandardWriter) Close() error {

	for zeekFileType, spoolFile := range w.spoolFiles {
		// Write the closing footer to our spool file
		err := WriteTSVFooter(zeekFileType, w.clock.Now(), spoolFile)
		if err != nil {
			return err
		}

		// close the file out, prepare for reading
		if err := spoolFile.Close(); err != nil {
			return err
		}

		// archive the spool file we just closed out
		srcFile, err := w.fs.Open(spoolFile.Name())
		if err != nil {
			return err
		}

		archiveName := fmt.Sprintf("%s.log.gz", zeekFileType.Header().Path)
		archivePath := path.Join(w.archiveDir, archiveName)

		// Open the gzip file and make sure it doesn't exist
		gzfile, err := w.fs.Create(archivePath)
		if err != nil {
			return err
		}
		gzout := gzip.NewWriter(gzfile)

		// copy contents from source file to gzip file
		size, err := io.Copy(gzout, srcFile)

		srcFile.Close()
		gzout.Close()
		gzfile.Close()

		if err != nil {
			return err
		}

		if err = w.fs.Remove(srcFile.Name()); err != nil {
			return err
		}

		log.Infof("Log written: %s    size: %d", archivePath, size)
	}

	return nil
}
