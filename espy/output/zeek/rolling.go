package zeek

import (
	"compress/gzip"
	"io"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/activecm/BeaKer/espy/input"
	"github.com/activecm/BeaKer/espy/output"
	"github.com/robfig/cron"
)

// Scheduled rolling log writer, expect timings

// RollingWriter is our continuous writer, expects
// packet sessions in and will print to a spool file
// until the end of the hour and will rotate them
type RollingWriter struct {
	zeekDir     string
	spoolDir    string
	spoolFile   string
	debug       bool
	scheduler   *cron.Cron
	file        *os.File
	rotateMutex *sync.Mutex
	crashFunc   func()
}

// CreateRollingWritingSystem constructs new rolling writer system
func CreateRollingWritingSystem(tgtDir string, crashFunc func(), debug bool) (output.ECSWriter, error) {
	w := &RollingWriter{}
	w.debug = debug
	w.zeekDir = tgtDir
	w.spoolDir = tgtDir + "/ecs-spool"
	w.spoolFile = w.spoolDir + "/conn.log"
	w.rotateMutex = new(sync.Mutex)
	w.crashFunc = crashFunc
	err := w.initWriterSchedule()
	if err != nil {
		return nil, err
	}
	w.file, err = initSpoolFile(w.spoolFile, w.spoolDir)
	if err != nil {
		return nil, err
	}

	log.Info("Initialized rolling file writer")
	return w, nil
}

func (w *RollingWriter) initWriterSchedule() (err error) {
	w.scheduler = cron.New()
	if w.debug {
		// Run every minute on the 0th second
		err = w.scheduler.AddFunc("0 * * * * *", w.rotateLogsWrapper)
		log.Infof("Rotating logs every minute at: %s", w.spoolDir)
	} else {
		// Run every hour
		err = w.scheduler.AddFunc("0 0 * * * *", w.rotateLogsWrapper)
		log.Infof("Rotating logs every hour at: %s", w.spoolDir)
	}
	if err != nil {
		return err
	}
	w.scheduler.Start()

	return nil
}

// AddSessionToWriter adds additional sessions to our writer
func (w *RollingWriter) AddSessionToWriter(outputdata []*input.ECSSession) error {
	w.rotateMutex.Lock()
	defer w.rotateMutex.Unlock()
	log.Debugf("Writing %d records", len(outputdata))
	return writeLine(outputdata, w.file)
}

// Close will close out the file progress and save everything
// from spool to main log output
func (w *RollingWriter) Close() error {
	return w.rotateLogs(true)
}

func (w *RollingWriter) rotateLogsWrapper() {
	err := w.rotateLogs(false)
	if err != nil {
		log.WithError(err).
			WithField("fatal", true).
			Error("Could not perform scheduled log rotation")
		// let the rest of the system know we had a fatal error
		// in the cron scheduling thread
		w.scheduler.Stop()
		w.crashFunc()
	}
}

func (w *RollingWriter) rotateLogs(close bool) error {
	w.rotateMutex.Lock()
	defer w.rotateMutex.Unlock()

	outName := w.getOutputFilename(time.Now())
	if !close {
		log.Debug("About to rotate logs")
	} else {
		log.Debug("Closing files")
	}

	currTime := time.Now()
	closeStr := currTime.Format("#close	2006-01-02-15-04-05\n")
	dirdate := currTime.Format("/2006-01-02")

	if err := os.MkdirAll(w.zeekDir+dirdate, 0755); err != nil {
		return err
	}

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
	gzfile, err := os.Create(outName)
	if err != nil {
		return err
	}
	gzout := gzip.NewWriter(gzfile)

	// copy contents from source file to gzip file
	size, err := io.Copy(gzout, srcFile)

	log.Debugf("Copied %s to %s", srcFile.Name(), gzfile.Name())

	srcFile.Close()
	gzout.Close()
	gzfile.Close()

	if err != nil {
		return err
	}

	if err = os.Remove(srcFile.Name()); err != nil {
		return err
	}

	log.Infof("Log written: %s    size: %d", outName, size)

	// Spool gets deleted, we must remake it if we're not closing

	if !close {
		log.Debug("About to re-create spool file")
		w.file, err = initSpoolFile(w.spoolFile, w.spoolDir)
		if err != nil {
			return err
		}

		log.Debugf("Rolled over logs, created new spool directory in %s", w.spoolDir)
	}
	return nil
}

func (w *RollingWriter) getOutputFilename(fileTime time.Time) string {
	if w.debug {
		startTime := fileTime.Add(-1 * time.Minute)
		return w.zeekDir + startTime.Format("/2006-01-02") + "/" +
			"conn." + startTime.Format("15:04:00") + "-" +
			fileTime.Format("15:04:05") + ".log.gz"
	}
	startTime := fileTime.Add(-1 * time.Hour)
	return w.zeekDir + startTime.Format("/2006-01-02") + "/" +
		"conn." + startTime.Format("15:00:00") + "-" +
		fileTime.Format("15:00:00") + ".log.gz"
}
