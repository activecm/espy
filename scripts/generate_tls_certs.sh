#!/usr/bin/env bash

# This script will generate an x509 rsa certificate and key if
# the files do not exist already.

# Change dir to script dir
pushd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" > /dev/null

# Load the function library
. ./shell-lib/acmlib.sh
normalize_environment
require_sudo

ESPY_CONFIG_DIR="${ESPY_CONFIG_DIR:-/etc/espy}"
CERTIFICATE_DIR="$ESPY_CONFIG_DIR/certificates"


PUBLIC_CRT="$CERTIFICATE_DIR/redis.crt"
PRIVATE_KEY="$CERTIFICATE_DIR/redis.key"

# Initializes the global certs if they don't exist
main() {
	# This check is unnecessary with mkdir -p but avoids an unconditional
	# sudo that would force a password prompt every time
	if [ ! -d "$CERTIFICATE_DIR" ]; then
		echo2 "Certificate directory not found. Creating: $CERTIFICATE_DIR"
		$SUDO mkdir -p "$CERTIFICATE_DIR"
	fi

	if [ ! -f "$PUBLIC_CRT" ] || [ ! -f "$PRIVATE_KEY" ]; then
		# If one or the other is found but not both remove them and start over
		if [ -f "$PUBLIC_CRT" ]; then $SUDO rm -f "$PUBLIC_CRT"; fi
		if [ -f "$PRIVATE_KEY" ]; then $SUDO rm -f "$PRIVATE_KEY"; fi

		echo2 "No certificates found. Generating..."
		$SUDO openssl req -x509 -newkey rsa:4096 \
		-keyout "$PRIVATE_KEY" -out "$PUBLIC_CRT" \
		-days 1825 -nodes > /dev/null 2>&1 << HERE
US
Some-State

Active Countermeasures
Espy
localhost

HERE
    else
        echo2 "Existing certificates found. Exiting..."
	fi

    $SUDO chown -R root:docker "$CERTIFICATE_DIR"
    $SUDO chmod 640 "$CERTIFICATE_DIR"/*
}

# Ensure the certificates exist
main

# Change back to original directory
popd > /dev/null
