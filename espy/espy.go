package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"

	"github.com/activecm/BeaKer/espy/config"
	"github.com/activecm/BeaKer/espy/input"
	"github.com/activecm/BeaKer/espy/output"
	"github.com/activecm/BeaKer/espy/output/zeek"
)

// command line flags
var (
	configFlag = flag.String(
		"config",
		"",
		"Use a given `CONFIG_FILE` instead of "+config.DefaultConfigPath,
	)

	versionFlag = flag.Bool(
		"version",
		false,
		"Print the version and exit immediately",
	)
)

//linkContextToInterrupt creates a child context which is cancelled when
//the program receives an interrupt
func linkContextToInterrupt(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancelCtx := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cancelCtx()
	}()
	return ctx, cancelCtx
}

//isContextCancelled returns true if a context has been cancelled
func isContextCancelled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}
	return false
}

func main() {
	// parse command line flags into globally defined options above
	flag.Parse()
	log.SetLevel(log.InfoLevel)
	if *versionFlag {
		log.Info(config.ExactVersion)
		return
	}

	log.Info("Welcome to Espy by Active Countermeasures!")
	conf, err := config.LoadConfig(*configFlag)
	if err != nil {
		log.WithError(err).Fatal("Could not load configuration file")
	}
	log.SetLevel(log.Level(conf.S.LogLevel))

	// create context to coordinate async shutdown
	ctx, ctxCancelFunc := linkContextToInterrupt(context.Background())

	// set up Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     conf.S.Redis.Host,
		Username: conf.S.Redis.User,
		Password: conf.S.Redis.Password,
	})
	if conf.R.Redis.TLSConfig != nil {
		redisClient.Options().TLSConfig = conf.R.Redis.TLSConfig
	}

	// set up Elasticsearch connection
	var esWriter output.JSONWriter
	if conf.S.Elasticsearch.Host != "" {
		log.Infof("Enabling Elasticsearch output at %s", conf.S.Elasticsearch.Host)
		esWriter = output.NewElasticWriter(conf.S.Elasticsearch, conf.R.Elasticsearch)
	} else {
		log.Info("Disabling Elasticsearch output")
	}

	// set up zeek file writer
	var zeekWriter output.ECSWriter
	if conf.S.Zeek.RotateLogs {
		zeekWriter, err = zeek.CreateRollingWritingSystem(
			conf.S.Zeek.OutputPath, ctxCancelFunc,
		)
	} else {
		zeekWriter, err = zeek.CreateStandardWritingSystem(conf.S.Zeek.OutputPath)
	}

	if err != nil {
		log.WithError(err).Error("Failed to initialize Zeek writer. Shutting down.")
		return
	}

	for !isContextCancelled(ctx) {

		//try to get more data to process
		netMessage, err := redisClient.BLPop(ctx, time.Second, "net-data:sysmon" /*, "net-data:packetbeat"*/).Result()

		if err == redis.Nil {
			// Read timeout but no exit signal, keep polling Redis
			log.WithError(err).Debug("Timed out while polling Redis for data.")
			continue
		} else if err != nil {
			log.WithError(err).Error("Could not read data from Redis.")
			break
		}

		//send message to elasticsearch
		if esWriter != nil {
			err = esWriter.AddSessionToWriter(netMessage[1])
			if err != nil {
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not connect to Elasticsearch.")
			}
		}

		//parse data and send it to zeek writer
		ecsData := input.ECSSession{}
		err = json.Unmarshal([]byte(netMessage[1]), &ecsData)
		if err != nil {
			log.WithError(err).WithField("input", netMessage[1]).Error("Could not parse JSON data.")
			continue
		}

		err = zeekWriter.AddSessionToWriter([]*input.ECSSession{&ecsData})
		if err != nil {
			if err == zeek.ErrMalformedECSSession {
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not read malformed ECS data")
				continue
			} else {
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not write Zeek data.")
				break
			}
		}
	}
	log.Warn("Shutting down.")
	ctxCancelFunc() // in case we got here via an error rather than exit signal
	err = zeekWriter.Close()
	if err != nil {
		log.WithError(err).Error("Error encountered while closing Zeek writer.")
	}
}
