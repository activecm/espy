package output

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/activecm/espy/espy/config"
	log "github.com/sirupsen/logrus"
)

type ElasticWriter struct {
	config.ESStaticCfg
	httpClient http.Client
}

//NewElasticWriter returns a JSONWriter which sends JSON document to
//an Elasticsearch index
func NewElasticWriter(static config.ESStaticCfg, running config.ESRunningCfg) JSONWriter {
	writer := ElasticWriter{
		ESStaticCfg: static,
	}
	if running.TLSConfig != nil {
		writer.httpClient.Transport = &http.Transport{
			TLSClientConfig: running.TLSConfig,
		}
	}
	return writer
}

//targetIndex returns the name of the index to insert documents into
func (e ElasticWriter) targetIndex() string {
	today := time.Now()
	//TODO: Make this configurable
	return fmt.Sprintf("sysmon-%s", today.Format("2006-01-02"))
}

//WriteECSRecords sends the outputData to Elasticsearch
func (e ElasticWriter) WriteECSRecords(outputData string) error {
	targetIndex := e.targetIndex()
	esHostURL := fmt.Sprintf("https://%s/%s/_doc", e.Host, e.targetIndex())
	reader := strings.NewReader(outputData)
	request, err := http.NewRequest("POST", esHostURL, reader)
	if err != nil {
		log.WithError(err).WithField("input", outputData).Error("Could not create HTTP request to handoff data to Elasticsearch.")
	}
	request.SetBasicAuth(e.User, e.Password)
	request.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(request)
	if err == nil && (resp == nil || resp.StatusCode < 200 || resp.StatusCode > 299) {
		httpCode := -1
		if resp != nil {
			httpCode = resp.StatusCode
		}
		err = fmt.Errorf("elasticsearch HTTP Error: %d", httpCode)
	}
	if err == nil {
		log.Debugf("[%d] OK Data transferred to Elasticsearch: %s", resp.StatusCode, targetIndex)
		resp.Body.Close()
	}
	return err
}

//Close does nothing for the ElasticWriter since each document is written
//with its own TCP session. This will likely be needed if we implement the Bulk API.
func (e ElasticWriter) Close() error {
	return nil
}
