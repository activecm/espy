#!/usr/bin/env bash
#Performs installation of Espy software
#version = 1.0.0

#### Environment Set Up

# Set the working directory to the script directory
pushd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null

# Set exit on error
set -o errexit
set -o errtrace
set -o pipefail

# ERROR HANDLING
__err() {
    echo2 ""
    echo2 "Installation failed on line $1:$2."
    echo2 ""
	exit 1
}

__int() {
    echo2 ""
	echo2 "Installation cancelled."
    echo2 ""
	exit 1
}

trap '__err ${BASH_SOURCE##*/} $LINENO' ERR
trap '__int' INT

# Load the function library
. ./shell-lib/acmlib.sh
normalize_environment

ESPY_CONFIG_DIR="${ESPY_CONFIG_DIR:-/etc/espy/}"

test_system () {
    status "Checking minimum requirements"
    require_supported_os
    require_free_space_MB "$HOME" "/var/lib" "/etc" "/usr" 5120
}

install_docker () {
    status "Installing Docker"
    $SUDO shell-lib/docker/install_docker.sh
    echo2 ''
    if $SUDO docker ps &>/dev/null ; then
		echo2 'Docker appears to be working, continuing.'
	else
        fail 'Docker does not appear to be working. Does the current user have sudo or docker privileges?'
	fi
}

install_configuration () {
    status "Generating Espy configuration"

    $SUDO mkdir -p "$ESPY_CONFIG_DIR"

    ensure_env_file_exists

    ensure_config_files_exist
}

ensure_env_file_exists () {
    if [ ! -f "$ESPY_CONFIG_DIR/env" ]; then
        cat << EOF | $SUDO tee "$ESPY_CONFIG_DIR/env" > /dev/null
###############################################################################
# By putting variables in this file, they will be made available to use in
# your Docker Compose files, including to pass to containers. This file must
# be named ".env" in order for Docker Compose to automatically load these
# variables into its working environment.
#
# https://docs.docker.com/compose/environment-variables/#the-env-file
###############################################################################

###############################################################################
# Espy Settings
#
ESPY_CONFIG_DIR=${ESPY_CONFIG_DIR}
#ESPY_ZEEK_LOGS=/alternative/zeek/output/path
###############################################################################
EOF
    fi

    $SUDO chown root:docker "$ESPY_CONFIG_DIR/env"
    $SUDO chmod 640 "$ESPY_CONFIG_DIR/env"

    if ! can_write_or_create ".env"; then
        sudo ln -sf "$ESPY_CONFIG_DIR/env" .env
    else
        ln -sf "$ESPY_CONFIG_DIR/env" .env
    fi
}

ensure_config_files_exist () {
    # both espy and redis config files already exist
    if [ -f "$ESPY_CONFIG_DIR/espy.conf" -a -f "$ESPY_CONFIG_DIR/redis.conf" ]; then
        return
    fi

    # back up espy config if it exists but redis config does not
    if [ -f "$ESPY_CONFIG_DIR/espy.conf" ]; then
        mv "$ESPY_CONFIG_DIR/espy.conf.bak"
    fi

    # back up redis config if it exists but espy config does not
    if [ -f "$ESPY_CONFIG_DIR/redis.conf" ]; then
        mv "$ESPY_CONFIG_DIR/espy.conf.bak"
    fi

    local redis_admin_pw=`generate_password`
    local redis_net_recv_pw=`generate_password`
    local redis_net_agent_pw=`generate_password`

    local redis_template=`cat ./etc/redis.conf`
    local espy_template=`cat ./etc/espy.docker.conf`

    # do replacements in bash so as not to leak passwords
    local redis_config="${redis_template/ADMIN_SECRET_PLACEHOLDER/$redis_admin_pw}"
    redis_config="${redis_config/NET_RECEIVER_SECRET_PLACEHOLDER/$redis_net_recv_pw}"
    redis_config="${redis_config/NET_AGENT_SECRET_PLACEHOLDER/$redis_net_agent_pw}"

    local espy_config="${espy_template/NET_RECEIVER_SECRET_PLACEHOLDER/$redis_net_recv_pw}"

    cat << EOF | $SUDO tee "$ESPY_CONFIG_DIR/redis.conf" > /dev/null
$redis_config
EOF

cat << EOF | $SUDO tee "$ESPY_CONFIG_DIR/espy.yaml" > /dev/null
$espy_config
EOF

    echo2 "Use the following password to connect WinLogBeat to the Espy Redis Server:"
    printf "\t$redis_net_agent_pw\n" >&2
}

ensure_certificates_exist () {
    # TODO: certificates for redis
}

install_espy () {
    status "Installing Redis and the Espy service"

    # Determine if the current user has permission to run docker
    local docker_sudo=""
    if [ ! -w "/var/run/docker.sock" ]; then
        docker_sudo="sudo"
    fi

    # Load the docker images
    gzip -d -c images-latest.tar.gz | $docker_sudo docker load >&2

    # Start Elasticsearch and Kibana with the new images
    ./espy.sh up -d --force-recreate >&2

    status "Waiting for initialization"
    sleep 15
}

move_files () {
    local installation_dir="/opt/$(basename "$(pwd)")"
    if [[ `pwd` -ef "$installation_dir" ]]; then
        return 0
    fi

    status "Moving files to $installation_dir"
    $SUDO rm -rf "$installation_dir"
    move_working_directory `dirname "$installation_dir"`
}

link_executables () {
    local executables=(
        "./espy.sh"
    )

    for executable in "${executables[@]}"; do
        local executable_name=`basename "$executable"`
        local link_name="/usr/local/bin/$executable_name"
        $SUDO rm -f "$link_name"
        $SUDO ln -sf `realpath "$executable"` "$link_name"
    done
}

main () {
    status "Checking for administrator priviledges"
    require_sudo

    test_system

    move_files
    link_executables

    status "Installing supporting software"
    ensure_common_tools_installed

    install_docker

    install_configuration

    install_espy

    status "Congratulations, Espy is installed"
}

main "$@"

#### Clean Up
# Change back to the initial working directory
# If the script was launched from the script directory, popd will fail since it moved
popd &> /dev/null || true
