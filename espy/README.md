# espy
Endpoint detection for remote hosts for consumption by RITA and Elasticsearch

## Running Redis

In one terminal, bring up the server:
```sh
export ESPY_CONFIG_DIR=`realpath ./etc`  # Tell espy where to find config files
sudo -E docker-compose up redis-server
```

In the other terminal, bring up the redis cli:
```sh
sudo docker-compose up redis-cli
redis> AUTH admin ADMIN_SECRET_PLACEHOLDER
redis>
```

## Running Espy
First bring up the `redis-server`
Then, run
```
go build
./espy
```

Note that it takes some time for the program to shut down once you exit via CTRL-C.

## Sending Data To Espy
Check out the BeaKer install script for an example of how to set up Sysmon and Winlogbeat:
https://github.com/activecm/BeaKer/blob/master/agent/install-sysmon-beats.ps1

- On a machine running Windows 10, install Sysmon and Winlogbeat.
- Edit the `winlogbeat.yml` in the repo to point towards the machine running the `redis-server`
- Load the `sysmon-net-only.xml` and `winlogbeat.yml` config files included in the repo



