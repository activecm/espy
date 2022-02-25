package zeek

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/activecm/espy/espy/input"
	"github.com/activecm/espy/espy/output"
	"github.com/robfig/cron"
)

// rotateOnMinute tells the rolling writer to rotate the
// Zeek logs every minute rather than every hour. This may help
// when debugging. Note that this *MUST* remain a const and not a var
// so as not to create spaghetti code.
const rotateOnMinute = false

// RollingWriter is our continuous writer, expects
// packet sessions in and will print to a spool file
// until the end of the hour and will rotate them
type RollingWriter struct {
	archiveDir string
	spoolDir   string

	spoolFiles map[ZeekTSVFile]*os.File

	scheduler   *cron.Cron
	rotateMutex *sync.Mutex
	crashFunc   func()
}

// CreateRollingWritingSystem constructs new rolling writer system
func CreateRollingWritingSystem(tgtDir string, crashFunc func()) (output.ECSWriter, error) {
	w := &RollingWriter{}
	w.archiveDir = tgtDir
	w.spoolDir = tgtDir + "/ecs-spool"

	w.spoolFiles = make(map[ZeekTSVFile]*os.File, len(RegisteredTSVFiles))
	for i := range RegisteredTSVFiles {
		fileName := fmt.Sprintf("%s.log", RegisteredTSVFiles[i].Header().Path)
		filePath := path.Join(w.spoolDir, fileName)

		var err error
		w.spoolFiles[RegisteredTSVFiles[i]], err = OpenTSVFile(RegisteredTSVFiles[i], filePath)
		if err != nil {
			return nil, err
		}
	}

	w.rotateMutex = new(sync.Mutex)
	w.crashFunc = crashFunc
	err := w.initWriterSchedule()
	if err != nil {
		return nil, err
	}

	log.Info("Initialized rolling file writer")
	return w, nil
}

func (w *RollingWriter) initWriterSchedule() (err error) {
	w.scheduler = cron.New()
	if rotateOnMinute {
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

// WriteECSRecords writes Elastic Common Schema records out to Zeek files
func (w *RollingWriter) WriteECSRecords(outputData []input.ECSRecord) error {
	w.rotateMutex.Lock()
	defer w.rotateMutex.Unlock()
	log.Debugf("Writing %d records", len(outputData))

	for zeekFileType, groupedData := range MapECSRecordsToTSVFiles(outputData) {
		err := WriteTSVLines(zeekFileType, groupedData, w.spoolFiles[zeekFileType])
		if err != nil {
			return err
		}
	}

	return nil
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

	if !close {
		log.Debug("About to rotate logs")
	} else {
		log.Debug("Closing files")
	}

	for zeekFileType, spoolFile := range w.spoolFiles {
		currTime := time.Now()

		// Write the closing footer to our spool file
		err := WriteTSVFooter(zeekFileType, currTime, spoolFile)
		if err != nil {
			return err
		}

		// close the file out, prepare for reading
		if err := spoolFile.Close(); err != nil {
			return err
		}

		// archive the spool file we just closed out
		srcFile, err := os.Open(spoolFile.Name())
		if err != nil {
			return err
		}

		dirDate := currTime.Format("2006-01-02")
		datedArchiveDir := path.Join(w.archiveDir, dirDate)
		if err := os.MkdirAll(datedArchiveDir, 0755); err != nil {
			return err
		}

		archivePath := w.archivePathForFile(zeekFileType, currTime)

		// Open the gzip file and make sure it doesn't exist
		gzfile, err := os.Create(archivePath)
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

		log.Infof("Log written: %s    size: %d", archivePath, size)

		// Spool gets deleted, we must remake it if we're not closing
		if !close {
			log.Debug("About to re-create spool file")
			w.spoolFiles[zeekFileType], err = OpenTSVFile(zeekFileType, spoolFile.Name())
			if err != nil {
				return err
			}

			log.Debugf("Rolled over logs, created new spool directory in %s", w.spoolDir)
		}
	}
	return nil
}

func (w *RollingWriter) archivePathForFile(zeekFileType ZeekTSVFile, fileTime time.Time) string {
	path := zeekFileType.Header().Path
	if rotateOnMinute {
		startTime := fileTime.Add(-1 * time.Minute)
		return w.archiveDir + startTime.Format("/2006-01-02") + "/" +
			path + "." + startTime.Format("15:04:00") + "-" +
			fileTime.Format("15:04:05") + ".log.gz"
	} // else rotate on the hour
	startTime := fileTime.Add(-1 * time.Hour)
	return w.archiveDir + startTime.Format("/2006-01-02") + "/" +
		path + "." + startTime.Format("15:00:00") + "-" +
		fileTime.Format("15:00:00") + ".log.gz"
}
