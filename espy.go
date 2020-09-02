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
)

//TODO: Move this to its own file.
type ECSFlowData struct {
	RFCTimestamp string `json:"@timestamp"`
	Agent        struct {
		Hostname string
	}
	Source struct {
		IP      string
		Port    int
		Bytes   int64
		Packets int64
	}
	Destination struct {
		IP      string
		Port    int
		Bytes   int64
		Packets int64
	}
	Network struct {
		Transport string // RITA Proto
		Protocol  string // RITA Service
	}
	Event struct {
		Duration float64
	}
}

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

	//zeekPAth is the directory to write Zeek data out to
	//zeekPath = flag.String("zeek-path", "/opt/zeek/logs", "Folder in which to write Zeek logs")

	// oneShot determines whether the program will rotate logs or not
	//oneShot = flag.Bool("one-shot", false, "Export all log records to a single file")
)

//linkContextToInterrupt creates a child context which is cancelled when
//the program receives an interrupt
func linkContextToInterrupt(ctx context.Context) context.Context {
	ctx, cancelCtx := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cancelCtx()
	}()
	return ctx
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

	ctx := linkContextToInterrupt(context.Background())

	client := redis.NewClient(&redis.Options{
		Addr:     *redisHost,
		Username: *redisUser,
		Password: *redisSecret,
	})

	for {
		netMessage, err := client.BLPop(ctx, 0, "net-data:sysmon" /*, "net-data:packetbeat"*/).Result()
		if err != nil {
			log.WithError(err).Error("Could not read data from Redis. Shutting down.")
			break
		}

		ecsFlowData := ECSFlowData{}
		err = json.Unmarshal([]byte(netMessage[1]), &ecsFlowData)
		if err != nil {
			log.WithError(err).WithField("input", netMessage[1]).Error("Could not parse JSON data.")
			continue
		}

		log.Debug(fmt.Sprintf("%+v", ecsFlowData))
	}

}
