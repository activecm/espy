package zeek

import (
	"compress/gzip"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/activecm/BeaKer/espy/input"
	"github.com/activecm/BeaKer/espy/output"
)

// No scheduling, single dump file

// StandardWriter is our standard, single output
// file, will first write everything to single
// spool then move them to an appropriate, time
// stamped log file
type StandardWriter struct {
	zeekDir     string
	spoolDir    string
	outFileName string
	spoolFile   string
	debug       bool
	file        *os.File
}

// CreateStandardWritingSystem Creates a single shot writer system
func CreateStandardWritingSystem(tgtDir string, debug bool) (output.ECSWriter, error) {
	var err error
	w := &StandardWriter{}
	w.debug = debug
	w.zeekDir = tgtDir
	w.spoolDir = tgtDir + "/ecs-spool"
	w.outFileName = w.zeekDir + "/conn.log.gz"
	w.spoolFile = w.spoolDir + "/conn.log"
	w.file, err = initSpoolFile(w.spoolFile, w.spoolDir)
	if err != nil {
		return nil, err
	}
	log.Info("Initialized standard file writer")
	return w, nil
}

// AddSessionToWriter adds more session data to current session
func (w *StandardWriter) AddSessionToWriter(outputData []*input.ECSSession) error {
	log.Debugf("Writing %d records", len(outputData))
	return writeLine(outputData, w.file)
}

// Close will close all open sessions and rotate everything
// from spool data to logs
func (w *StandardWriter) Close() error {
	currTime := time.Now()
	closeStr := currTime.Format("#close	2006-01-02-15-04-05\n")

	// Write closing string to our spool file
	if _, err := w.file.Write([]byte(closeStr)); err != nil {
		return err
	}

	// close the file out, prepare for reading
	if err := w.file.Close(); err != nil {
		return err
	}

	srcFile, err := os.Open(w.spoolFile)
	if err != nil {
		return err
	}

	// Open the gzip file
	// make sure it doesn't exist
	gzfile, err := os.Create(w.outFileName)
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

	if err = os.Remove(srcFile.Name()); err != nil {
		return err
	}

	log.Infof("Log written: %s    size: %d", w.outFileName, size)
	return nil
}
