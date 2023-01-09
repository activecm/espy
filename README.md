# Espy - Sysmon Network Log Collector and Adapter

Brought to you by [Active Countermeasures](https://www.activecountermeasures.com/).

---

Espy collects Microsoft Sysmon network and DNS events in Elastic ECS format and
adapts it for use with other tools. Currently, Espy supports
converting Sysmon network connection events into Zeek TSV entries.

In addition, Espy optionally forwards data to an external Elasticsearch
server such as the one included in [BeaKer](https://github.com/activecm/BeaKer).

## How it works

- Microsoft Sysmon: Logs network connections to the Windows Event Log
- WinLogBeats: Sends the network connection logs to Elasticsearch
- Redis: Collects the network connection logs
- Espy service: Converts network logs into Zeek format and optionally forwards logs to Elasticsearch

## Installation

### Espy Server System Requirements
* Operating System: The preferred platform is x86 64-bit Ubuntu 20.04 LTS. The system should be patched and up to date using apt-get.
  * The automated installer will also support CentOS 7.
* Processor: At least two cores.
* Memory: 8-16GB. Monitoring more hosts requires more RAM.
* Storage: Ensure `/opt/zeek/logs` has free space for the incoming network logs.

### Espy Agent System Requirements
* Operating System: Windows x86-64 bit OS

### Automated Install: Espy Server

Download the latest release tar file, extract it, and inside the `Espy` directory,
run `./install_espy.sh` on the Linux machine that will collect your Sysmon data and store the resulting Zeek logs.

The automated installer will:
  - Install Docker and Docker-Compose
  - Create a configuration directory in `/etc/espy`
  - Install Redis and the Espy service
  - Generate credentials for connecting to Redis

The `./espy.sh` script inside of the release tar file is a wrapper around `docker-compose` and can be used to manage Espy.
 - To stop Espy, run `./espy.sh down`
 - To start Espy, run `./espy.sh up`
 - To view the logs of the Redis container, run `./espy.sh logs -f espy_redis_1`
 - To view the logs of the Espy service container, run `./espy.sh logs -f espy_espy_1`

After running `./install_espy.sh` you should be able to access Redis at `localhost:6379`. Note that Redis is exposed on every network interface available on the Docker host.

The Espy service will begin writing Zeek TSV formatted log data out to `/opt/zeek/logs` and will rotate the log files each hour.

The easiest way to begin sending data to the server is to use the automated Espy agent installer.

### Automated Install: Espy Agent
The PowerShell script `./agent/install-sysmon-beats.ps1` will install Sysmon and WinLogBeats, and configure WinLogBeats to begin sending data to the Espy Redis server.

To install the agent, run the script as `.\install-sysmon-beats.ps1 ip.or.hostname.of.espy.server`.

The script then:
- Asks for the password for the Redis server to connect to
  - This may be supplied using the parameter `RedisPassword`
  - If using the automated Espy Server installer, use the value printed during the server installation
- Downloads Sysmon and installs it in `%PROGRAMFILES%` if it doesn't exist
  - Creates a new configuration file at `%PROGRAMFILES%\Sysmon\sysmon-espy.xml`
  - If Sysmon was previously installed, the old configuration will be merged with the configuration necessary to run Espy
- Ensures Sysmon is running as a service with the new `sysmon-espy.xml` configuration file
- Downloads WinLogBeat and installs it in `%PROGRAMFILES%` and `%PROGRAMDATA%` if it doesn't exist
  - Creates a new `winlogbeat.yml` file to connect to the Espy Redis server
  - If `winlogbeat.yml` was previously installed:
    - The old configuration will be backed up to `winlogbeat.yml.bak`
    - The old configuration will be merged with the configuration necessary to run Espy
    - This merging process may fail. If this happens the script will prompt you to manually edit the `winlogbeat.yml` configuration file.
    - Run `stop-service winlogbeat; start-service winlogbeat` after editing the `winlogbeat.yml` file
- Ensures WinLogBeat is running as a service with the new `winlogbeat.yml` configuration file

### Forwarding Events to BeaKer's Elasticsearch Instance
One of our open source tools, [BeaKer](https://github.com/activecm/BeaKer), uses Elasticsearch with Kibana dashboards. If you wish to forward the log events for all of the Windows hosts running the Espy agent to BeaKer's Elasticsearch instance, there are some configuration changes needed.

- Find the address of Docker's network bridge (default is `172.17.0.1`):
  - `docker network inspect bridge --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`
  or
  - `ip -br -c -f inet addr show docker0`
  
In `/etc/espy/espy.yaml`, edit the `Elasticsearch` block as follows:

```
Elasticsearch:
  # Set the host to the address of Docker's network bridge.
  Host: "172.17.0.1:9200"
  # Use the credentials created for BeaKer's ingestion tasks.
  # If the automated installer for BeaKer was used, the account is sysmon-ingest.
  User: "sysmon-ingest"
  # If you forgot the password for the sysmon-ingest user, it can be reset within Kibana under Management>Security>Users
  # Resetting the password requires updating each Windows system running the BeaKer agent with the new password
  Password: "password"

  TLS:
    # TLS must be enabled.
    Enable: true
    # Do not verify certs or provide a CA file if using the automated installer.
    VerifyCertificate: false
    CAFile: ""
```

Note that the configuration example sets the `Host` to the address of Docker's network bridge. This is a quick way to get Espy hooked up to BeaKer. If your network or Docker installation has a non-standard configuration, this change may not work. 

Why?

BeaKer exposes port `9200` for Elasticsearch, so the Elastic instance runs on the [Docker host's](https://www.google.com/search?q=docker+host) loopback address (`localhost`, `127.0.0.1`). This means that Elasticsearch/Kibana is accessible on your server/network and is not isolated to the Docker containers/network.
Espy exposes port `6379` for Redis, so Redis is accessible on your server/network, and therefore is able to receive logs from endpoints with the Espy agent installed. Since winlogbeat only supports one output source, we cannot directly pass logs over to Elasticsearch and instead must forward logs over from Redis/Espy. Since Espy's event forwarder runs in a container, it does not have access to the server's loopback address via `localhost` or `127.0.0.1`. Therefore, setting the `Host` field in `espy.yaml` to `localhost:9200` or `127.0.0.1:9200` would be pointing to the Espy container's loopback address, which does not host the Elastic instance, so it would fail. 

There are multiple ways to get a Docker container to be able to connect to the Docker host's network. [This tutorial](https://www.howtogeek.com/devops/how-to-connect-to-localhost-within-a-docker-container/) shows a few of those methods. If using `172.17.0.1` as the Elastic host address doesn't work for you, maybe some of these other methods will. Some methods do impose security risks, so be sure to review what would be exposed with each method. 
One thing to note is that the forwarder receives the value of the `Host` parameter as a string, so using any Docker based variables that are usually used in Compose or Dockerfiles would not work unless Docker literally translates the routing address to the name of the variable. (i.e Can the Espy container reach `https://host.docker.internal:9200/` ?)

### Data Collected By Sysmon Per Network Connection
- Source
  - IP Address
  - Hostname
  - Port
- Destination
  - IP Address
  - Hostname
  - Port
- Network
  - Transport Protocol
  - Application Protocol
  - Community ID
- Process
  - PID
  - Executable
  - Entity ID
- User
  - Domain
  - Name
- Timestamp

### Data Collected By Sysmon Per DNS Lookup
- Host 
  - IP
- DNS
  - Question
    - Name
  - Answers
    - Type
    - Data

## Developer Information

To generate a new release tarball, run `./scripts/installer/generate_installer.sh`.

To build the Espy service natively:
- Install Go 1.14 or later
- Install `make`
- Clone the git repository
- `cd` into the `espy` subdirectory and run `make`
- The resulting executable is located at `./espy/espy`

To run the native Espy service:
- Copy the `./espy/etc/espy.yaml` file to `/etc/espy/espy.yaml`
- Start Redis
- Edit `/etc/espy/espy.yaml` to point to your Redis server
- Start the Espy service with `./espy/espy`

To run the Espy service and Redis in Docker, without installing:
- Copy the `./espy/etc/espy.docker.yaml` file to `/etc/espy/espy.yaml`
- Copy the `./redis/redis.conf` file to `/etc/espy/redis.conf`
- Start the Espy service and Redis with `./espy.sh up`

The default credentials for development are:
- Default Redis Password (used for connecting WinLogBeats): `NET_AGENT_SECRET_PLACEHOLDER`
- Redis Receiver Account (used by the Espy service):
  - Username: `net-receiver`
  - Password: `NET_RECEIVER_SECRET_PLACEHOLDER`
- Redis Admin Account:
  - Username: `admin`
  - Password: `ADMIN_SECRET_PLACEHOLDER`

To access a shell for Redis in Docker:
- Uncomment the `redis-cli` service definition in `docker-compose.yml`
- Run `./espy.sh up redis-cli`
- At the prompt, enter `AUTH admin ADMIN_SECRET_PLACEHOLDER`

## License

GNU GPL V3 © Active Countermeasures ™
