package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"

	yaml "gopkg.in/yaml.v2"
)

type (
	//StaticCfg is the container for other static config sections
	StaticCfg struct {
		Redis         RedisStaticCfg `yaml:"Redis"`
		Elasticsearch ESStaticCfg    `yaml:"Elasticsearch"`
		Zeek          ZeekCfg        `yaml:"Zeek"`
		LogLevel      int            `yaml:"LogLevel" default:"3"`
		Version       string
		ExactVersion  string
	}

	RedisStaticCfg struct {
		Host     string       `yaml:"Host"`
		User     string       `yaml:"User"`
		Password string       `yaml:"Password"`
		TLS      TLSStaticCfg `yaml:"TLS"`
	}

	ESStaticCfg struct {
		Host     string       `yaml:"Host"`
		User     string       `yaml:"User"`
		Password string       `yaml:"Password"`
		TLS      TLSStaticCfg `yaml:"TLS"`
	}

	ZeekCfg struct {
		OutputPath string `yaml:"Path" default:"/opt/zeek/logs"`
		RotateLogs bool   `yaml:"Rotate" default:"true"`
	}

	TLSStaticCfg struct {
		Enabled           bool   `yaml:"Enable" default:"false"`
		VerifyCertificate bool   `yaml:"VerifyCertificate" default:"false"`
		CAFile            string `yaml:"CAFile" default:""`
	}
)

// readStaticConfigFile attempts to read the contents of the
// given cfgPath file path (e.g. /etc/rita/config.yaml)
func readStaticConfigFile(cfgPath string) ([]byte, error) {
	_, err := os.Stat(cfgPath)

	if os.IsNotExist(err) {
		return nil, err
	}

	cfgFile, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}

	return cfgFile, nil
}

// parseStaticConfig loads the yaml from cfgFile into the provided config struct.
// It also fixes up misc values that need tweaking into the right format.
func parseStaticConfig(cfgFile []byte, config *StaticCfg) error {
	err := yaml.Unmarshal(cfgFile, config)

	if err != nil {
		return err
	}

	// expand env variables, config is a pointer
	// so we have to call elem on the reflect value
	expandConfig(reflect.ValueOf(config).Elem())

	// clean all filepaths
	config.Zeek.OutputPath = filepath.Clean(config.Zeek.OutputPath)
	config.Redis.TLS.CAFile = filepath.Clean(config.Redis.TLS.CAFile)
	config.Elasticsearch.TLS.CAFile = filepath.Clean(config.Elasticsearch.TLS.CAFile)

	// grab the version constants set by the build process
	config.Version = Version
	config.ExactVersion = ExactVersion

	return nil
}

// expandConfig expands environment variables in config strings
func expandConfig(reflected reflect.Value) {
	for i := 0; i < reflected.NumField(); i++ {
		f := reflected.Field(i)
		// process sub configs
		if f.Kind() == reflect.Struct {
			expandConfig(f)
		} else if f.Kind() == reflect.String {
			f.SetString(os.ExpandEnv(f.String()))
		} else if f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.String {
			strs := f.Interface().([]string)
			for i, str := range strs {
				strs[i] = os.ExpandEnv(str)
			}
			f.Set(reflect.ValueOf(strs))
		}
	}
}
