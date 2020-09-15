package main

import (
	"context"
	"crypto/tls"
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

	"github.com/activecm/espy/input"
	"github.com/activecm/espy/output"
	"github.com/activecm/espy/output/zeek"
)

//const version = "Espy v0.0.1"

const debug = true

// command line flags
var (
	// version prints the version
	//versionFlag = flag.Bool("version", false, "Print version")

	//esHost is the optional Elasticsearch server to send data to
	//esHost = flag.String("es-host", "", "Elasticsearch host to write to")

	//redisHost is the Redis host to read net data from
	redisHost = flag.String("redis-host", "127.0.0.1:6379", "Redis host to read from")

	//redisUser is the Redis user to authenticate as
	redisUser = flag.String("redis-user", "net-receiver", "Redis user account name")

	//redisSecret is the Redis user secret to authenticate with
	redisSecret = flag.String("redis-pw", "NET_RECEIVER_SECRET_PLACEHOLDER", "Redis user secret")

	//elasticHost is the Elasticsearch host to send data to
	elasticHost = flag.String("elastc-host", "127.0.0.1:9200", "Elasticsearch host to read from")

	// elasticUser is the Elasticsearch user to authenticate as
	elasticUser = flag.String("elastic-user", "sysmon-ingest", "Elasticsearch user account name")

	//elasticPass is the Redis user secret to authenticate with
	elasticPass = flag.String("elastic-pw", "password", "Elasticsearch user password")

	//verbose controls how much is written to stdout
	verbose = flag.Bool("verbose", false, "log more information")

	//zeekPath is the directory to write Zeek data out to
	zeekPath = flag.String("zeek-path", "/opt/zeek/logs", "Folder in which to write Zeek logs")

	//disableRotate determines whether the program will rotate logs or not
	disableRotate = flag.Bool("disable-rotation", false, "Export all Zeek records to a single file")
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
	fmt.Println("Welcome to Espy by Active Countermeasures!")

	// parse command line flags into globally defined options  above
	flag.Parse()

	// if simple version request, proceed to exit
	// if *versionFlag {
	// 	fmt.Println(version)
	// 	os.Exit(0)
	// }

	if *verbose {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	ctx, ctxCancelFunc := linkContextToInterrupt(context.Background())

	client := redis.NewClient(&redis.Options{
		Addr:     *redisHost,
		Username: *redisUser,
		Password: *redisSecret,
	})

	var zeekWriter output.ECSWriter
	var err error
	if *disableRotate {
		zeekWriter, err = zeek.CreateStandardWritingSystem(*zeekPath, debug)
	} else {
		zeekWriter, err = zeek.CreateRollingWritingSystem(*zeekPath, ctxCancelFunc, debug)
	}

	if err != nil {
		log.WithError(err).Error("Failed to initialize Zeek writer. Shutting down.")
		return
	}

	for {
		netMessage, err := client.BLPop(ctx, 0, "net-data:sysmon" /*, "net-data:packetbeat"*/).Result()
		if err != nil {
			log.WithError(err).Error("Could not read data from Redis. Shutting down.")
			break
		}

		reader := strings.NewReader(netMessage[1])
		today := time.Now().UTC()
		request, err := http.NewRequest("POST", "https://"+*elasticHost+"/sysmon-"+today.Format("2006-01-02")+"/_doc", reader)
		if err != nil {
			log.WithError(err).WithField("input", netMessage[1]).Error("Could not create HTTP request to handoff data to Elasticsearch.")
		}

		// TODO: Properly handle invalid Elasticsearch certs
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		request.SetBasicAuth(*elasticUser, *elasticPass)
		request.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(request)
		if err != nil || resp == nil {
			log.WithError(err).WithField("input", netMessage[1]).Error("Could not connect to Elasticsearch.")
		} else {
			fmt.Print(resp)
			resp.Body.Close()
		}

		ecsData := input.ECSSession{}
		err = json.Unmarshal([]byte(netMessage[1]), &ecsData)
		if err != nil {
			log.WithError(err).WithField("input", netMessage[1]).Error("Could not parse JSON data.")
			continue
		}

		log.Debug(fmt.Sprintf("%+v", ecsData))
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
