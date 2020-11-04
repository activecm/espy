# Espy - Sysmon Network Log Collector and Adapter

Brought to you by [Active Countermeasures](https://www.activecountermeasures.com/).

---

Espy collects Microsoft Sysmon network events in Elastic ECS format and
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
* Operating System: The preferred platform is x86 64-bit Ubuntu 16.04 LTS. The system should be patched and up to date using apt-get.
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

The script will then:
- Ask for the password for the Redis server to connect to
  - This may be supplied using the parameter `RedisPassword`
  - If using the automated Espy Server installer, use the value printed during the server installation
- Download Sysmon and install it with the default configuration in `%PROGRAMFILES%` if it doesn't exist
- Ensures Sysmon is running as a service
- Download WinLogBeat and install it in `%PROGRAMFILES%` and `%PROGRAMDATA%` if it doesn't exist
- **Removes any existing winlogbeat configuration files (`winlogbeat.yml`)**
- Installs a new `winlogbeat.yml` file to connect to the Espy Redis server
- Ensures WinLogBeat is running as a service

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