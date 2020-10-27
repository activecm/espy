package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// set up redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     conf.S.Redis.Host,
		Username: conf.S.Redis.User,
		Password: conf.S.Redis.Password,
	})
	if conf.R.Redis.TLSConfig != nil {
		redisClient.Options().TLSConfig = conf.R.Redis.TLSConfig
	}

	// set up elastic connection
	esClient := &http.Client{}
	if conf.R.Elasticsearch.TLSConfig != nil {
		esClient.Transport = &http.Transport{
			TLSClientConfig: conf.R.Elasticsearch.TLSConfig,
		}
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

MainLoop:
	for {
		//try to get more data to process
		netMessage, err := redisClient.BLPop(ctx, time.Second, "net-data:sysmon" /*, "net-data:packetbeat"*/).Result()

		if err == redis.Nil || err == context.Canceled {
			select {
			case <-ctx.Done():
				// Read timeout and exit signal received. Shut down.
				log.WithError(err).Warn("Received exit signal. Shutting down.")
				break MainLoop
			default:
				log.WithError(err).Debug("Timed out while polling Redis for data.")
				// Read timeout but no exit signal, keep polling Redis
				continue
			}
		} else if err != nil {
			log.WithError(err).Error("Could not read data from Redis. Shutting down.")
			break MainLoop
		}

		//send message to elasticsearch
		if conf.S.Elasticsearch.Host != "" {
			reader := strings.NewReader(netMessage[1])
			today := time.Now()
			esHostURL := fmt.Sprintf("https://%s/sysmon-%s/_doc", conf.S.Elasticsearch.Host, today.Format("2006-01-02"))
			request, err := http.NewRequest("POST", esHostURL, reader)
			if err != nil {
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not create HTTP request to handoff data to Elasticsearch.")
			}
			request.SetBasicAuth(conf.S.Elasticsearch.User, conf.S.Elasticsearch.Password)
			request.Header.Set("Content-Type", "application/json")
			resp, err := esClient.Do(request)
			if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not connect to Elasticsearch.")
			} else {
				log.Debug(fmt.Sprintf("[%d] OK %s Data transferred to Elasticsearch", resp.StatusCode, today.Format("2006-01-02 3:04.000")))
				resp.Body.Close()
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
				log.WithError(err).WithField("input", netMessage[1]).Error("Could not write Zeek data. Shutting down.")
				break
			}
		}
	}

	err = zeekWriter.Close()
	if err != nil {
		log.WithError(err).Error("Error encountered while closing Zeek writer.")
	}
}
