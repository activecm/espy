package config

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/blang/semver"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
)

type (
	RunningCfg struct {
		Redis         RedisRunningCfg
		Elasticsearch ESRunningCfg
		Version       semver.Version
	}

	RedisRunningCfg struct {
		TLSConfig *tls.Config
	}

	ESRunningCfg struct {
		TLSConfig *tls.Config
	}
)

// initRunningConfig uses data in the static config initialize
// the passed in running config
func initRunningConfig(static *StaticCfg, running *RunningCfg) error {
	if static.Redis.TLS.Enabled {
		running.Redis.TLSConfig = parseStaticTLSConfig(&static.Redis.TLS)
	}

	if static.Elasticsearch.TLS.Enabled {
		running.Elasticsearch.TLSConfig = parseStaticTLSConfig(&static.Elasticsearch.TLS)
	}

	var err error
	running.Version, err = semver.ParseTolerant(static.Version)
	if err != nil {
		log.WithError(err).WithField("version", static.Version).Error(
			"Version error: please ensure that you cloned the git repo and are using make to build",
		)
	}
	return err
}

//parseStaticTLSConfig converts a TLSStaticCfg into a tls.Config for use
//with the golang net packages. If a CA file cannot be read, the error is logged
//and the system certificate pool is used instead.
func parseStaticTLSConfig(staticTLS *TLSStaticCfg) *tls.Config {
	tlsConf := &tls.Config{}
	if !staticTLS.VerifyCertificate {
		tlsConf.InsecureSkipVerify = true
	}

	finfo, err := os.Stat(staticTLS.CAFile)
	if err != nil && !finfo.IsDir() {
		pem, err := ioutil.ReadFile(staticTLS.CAFile)
		if err != nil {
			log.WithField("file", staticTLS.CAFile).WithError(err).Error("Could not read CA file")
		} else {
			tlsConf.RootCAs = x509.NewCertPool()
			tlsConf.RootCAs.AppendCertsFromPEM(pem)
		}
	}
	return tlsConf
}
