package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

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
