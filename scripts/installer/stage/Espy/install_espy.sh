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
. ./scripts/shell-lib/acmlib.sh
normalize_environment

ESPY_CONFIG_DIR="${ESPY_CONFIG_DIR:-/etc/espy}"
ESPY_ZEEK_LOGS="${ESPY_ZEEK_LOGS:-/opt/zeek/logs}"

test_system () {
    status "Checking minimum requirements"
    require_supported_os
    require_free_space_MB "$HOME" "/var/lib" "/etc" "/usr" "/opt" 5120
}

install_docker () {
    status "Installing Docker"
    $SUDO ./scripts/shell-lib/docker/install_docker.sh
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

    scripts/generate_tls_certs.sh
}

ensure_env_file_exists () {
    if [ ! -f "$ESPY_CONFIG_DIR/env" ]; then
        $SUDO touch "$ESPY_CONFIG_DIR/env"
        $SUDO chown root:docker "$ESPY_CONFIG_DIR/env"
        $SUDO chmod 640 "$ESPY_CONFIG_DIR/env"

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
ESPY_ZEEK_LOGS=${ESPY_ZEEK_LOGS}
###############################################################################
EOF
    fi

    if ! can_write_or_create ".env"; then
        sudo ln -sf "$ESPY_CONFIG_DIR/env" .env
    else
        ln -sf "$ESPY_CONFIG_DIR/env" .env
    fi
}


ensure_config_files_exist () {
    # both espy and redis config files already exist
    if [ -f "$ESPY_CONFIG_DIR/espy.yaml" -a -f "$ESPY_CONFIG_DIR/redis.conf" ]; then
        return
    fi

    # back up espy config if it exists but redis config does not
    if [ -f "$ESPY_CONFIG_DIR/espy.yaml" ]; then
        $SUDO mv "$ESPY_CONFIG_DIR/espy.yaml" "$ESPY_CONFIG_DIR/espy.yaml.bak"
    fi

    # back up redis config if it exists but espy config does not
    if [ -f "$ESPY_CONFIG_DIR/redis.conf" ]; then
        $SUDO mv "$ESPY_CONFIG_DIR/redis.conf" "$ESPY_CONFIG_DIR/redis.conf.bak"
    fi

    # generate new passwords
    local redis_admin_pw=`generate_password`
    local redis_net_recv_pw=`generate_password`
    local redis_net_agent_pw=`generate_password`

    # load configuration templates
    local redis_template=`cat ./etc/redis.conf`
    local espy_template=`cat ./etc/espy.docker.yaml`

    # do replacements in bash so as not to leak passwords
    local redis_config="${redis_template/ADMIN_SECRET_PLACEHOLDER/$redis_admin_pw}"
    redis_config="${redis_config/NET_RECEIVER_SECRET_PLACEHOLDER/$redis_net_recv_pw}"
    redis_config="${redis_config/NET_AGENT_SECRET_PLACEHOLDER/$redis_net_agent_pw}"

    local espy_config="${espy_template/NET_RECEIVER_SECRET_PLACEHOLDER/$redis_net_recv_pw}"

    # handle elasticsearch configuration
#     prompt2 "Would you like to forward incoming network logs to an Elasticsearch server (Y/N)"
#     if askYN; then
#         local elastic_host=""
#         local elastic_user=""
#         local elastic_password=""
#         local pw_confirmation="foobar"

#         read -e -p "Elasticsearch IP address or hostname: " elastic_host
#         elastic_host="\"$elastic_host\""

#         echo2 "Please enter the Elasticsearch user account credentials."
#         read -e -p "Elasticsearch username: " elastic_user
#         elastic_user="\"$elastic_user\""

#         while [ "$elastic_password" != "$pw_confirmation" ]; do
#             read -es -p "Elasticsearch password: " elastic_password
#             echo ""
#             read -es -p "Elasticsearch password (Confirmation): " pw_confirmation
#             echo ""
#         done
#         elastic_password="\"$elastic_password\""

#         local elastic_tls="true"
#         local elastic_tls_verify="false"
#         local elastic_tls_ca_file="\"\""

#         prompt2 "Disable TLS (Y/N)"
#         if askYN; then
#             elastic_tls="false"
#         else
#             prompt2 "Validate certificate hostname and signature (Y/N)"
#             if askYN; then
#                 elastic_tls_verify="true"
#                 prompt2 "Use a custom certificate authority (Y/N)"
#                 if askYN; then
#                     read -e -p "CA file: " elastic_tls_ca_file
#                     elastic_tls_ca_file="\"$elastic_tls_ca_file\""
#                 fi
#             fi
#         fi

#         local es_config=""
#         read -r -d '' es_config << EOF || true # read always returns 1 on HEREDOC's since NUL delim is never found
# Elasticsearch:
#   Host: $elastic_host
#   User: $elastic_user
#   Password: $elastic_password
#   TLS:
#     Enable: $elastic_tls
#     VerifyCertificate: $elastic_tls_verify
#     CAFile: $elastic_tls_ca_file
# EOF

#         # HACK: this horrible bash pattern replacement changes out the template Elasticsearch configuration.
#         # We should really invest in installing yq or another yaml manipulation tool.
#         # Bash patterns aren't regex. * means match any character (including newlines).
#         # $'\n' is ANSI C escape for newline (https://www.gnu.org/software/bash/manual/bash.html#ANSI_002dC-Quoting)
#         # https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html#Shell-Parameter-Expansion
#         # Sed was not used since the replacement pattern contains confidential information and may be leaked by /proc.
#         espy_config="${espy_config/Elasticsearch:*CAFile:*\"$'\n'$'\n'/$es_config$'\n'$'\n'}"
#     fi

    # create and permission configuration files
    $SUDO touch "$ESPY_CONFIG_DIR/redis.conf"
    $SUDO chown root:docker "$ESPY_CONFIG_DIR/redis.conf"
    $SUDO chmod 640 "$ESPY_CONFIG_DIR/redis.conf"

    $SUDO touch "$ESPY_CONFIG_DIR/espy.yaml"
    $SUDO chown root:docker "$ESPY_CONFIG_DIR/espy.yaml"
    $SUDO chmod 640 "$ESPY_CONFIG_DIR/espy.yaml"

    # write out config files to secured files
    cat << EOF | $SUDO tee "$ESPY_CONFIG_DIR/redis.conf" > /dev/null
$redis_config
EOF

cat << EOF | $SUDO tee "$ESPY_CONFIG_DIR/espy.yaml" > /dev/null
$espy_config
EOF

    # inform user of agent password
    echo2 "Redis passwords are stored in $ESPY_CONFIG_DIR/redis.conf."
    echo2 "Use the following password to connect WinLogBeat to the Espy Redis Server:"
    printf "\t$redis_net_agent_pw\n\n" >&2
}


install_espy () {
    status "Installing Redis and the Espy service"

    $SUDO mkdir -p "$ESPY_ZEEK_LOGS"

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
