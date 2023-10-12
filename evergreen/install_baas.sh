#!/usr/bin/env bash
# This script will download all the dependencies for and build/start a Realm Cloud app server
# and will import a given app into it.
#
# Usage:
# ./evergreen/install_baas.sh -w {path to working directory} [-b git revision of baas] [-v] [-h]
#

# shellcheck disable=SC1091
# shellcheck disable=SC2164

set -o errexit
set -o pipefail
set -o functrace

# Adds a string to $PATH if not already present.
function pathadd() {
    if [ -d "$1" ] && [[ ":$PATH:" != *":$1:"* ]]; then
        PATH="$1${PATH:+":$PATH"}"
        export PATH
    fi
}

function setup_target_dependencies() {
    case "$(uname -s)" in
        Darwin)
            NODE_URL="https://s3.amazonaws.com/static.realm.io/evergreen-assets/node-v14.17.0-darwin-x64.tar.gz"
            JQ_DOWNLOAD_URL="https://s3.amazonaws.com/static.realm.io/evergreen-assets/jq-1.6-darwin-amd64"
        ;;
        Linux)
            NODE_URL="https://s3.amazonaws.com/static.realm.io/evergreen-assets/node-v14.17.0-linux-x64.tar.gz"
            JQ_DOWNLOAD_URL="https://s3.amazonaws.com/static.realm.io/evergreen-assets/jq-1.6-linux-amd64"
        ;;
        *)
            echo "Unsupported platform ${target}"
            exit 1
        ;;
    esac
}

function setup_baas_dependencies() {
    baas_directory="${1}"
    exit_code=0
    baas_contents_file="${baas_directory}/.evergreen/constants.sh"
    BAAS_PLATFORM=
    MONGODB_DOWNLOAD_URL=
    MONGOSH_DOWNLOAD_URL=
    GOLANG_URL=
    STITCH_SUPPORT_LIB_URL=
    LIBMONGO_URL=
    ASSISTED_AGG_URL=
    target="$(uname -s)"
    case "${target}" in
        Darwin)
            if [[ "$(uname -m)" == "arm64" ]]; then
                export GOARCH=arm64
                MONGODB_DOWNLOAD_URL="https://downloads.mongodb.com/osx/mongodb-macos-arm64-enterprise-6.0.0-rc13.tgz"
                MONGOSH_DOWNLOAD_URL="https://downloads.mongodb.com/compass/mongosh-1.5.0-darwin-arm64.zip"

                # Go's scheduler is not BIG.little aware, and by default will spawn
                # threads until they end up getting scheduled on efficiency cores,
                # which is slower than just not using them. Limiting the threads to
                # the number of performance cores results in them usually not
                # running on efficiency cores. Checking the performance core count
                # wasn't implemented until the first CPU with a performance core
                # count other than 4 was released, so if it's unavailable it's 4.
                GOMAXPROCS="$(sysctl -n hw.perflevel0.logicalcpu || echo 4)"
                export GOMAXPROCS
                BAAS_PLATFORM="Darwin_arm64"
            else
                export GOARCH=amd64
                MONGODB_DOWNLOAD_URL="https://downloads.mongodb.com/osx/mongodb-macos-x86_64-enterprise-5.0.3.tgz"
                BAAS_PLATFORM="Darwin_x86_64"
            fi
        ;;
        Linux)
            BAAS_PLATFORM="Linux_x86_64"
            # Detect what distro/version of Linux we are running on to download the right version of MongoDB to download
            # /etc/os-release covers debian/ubuntu/suse
            if [[ -e /etc/os-release ]]; then
                # Amazon Linux 2 comes back as 'amzn'
                DISTRO_NAME="$(. /etc/os-release ; echo "${ID}")"
                DISTRO_VERSION="$(. /etc/os-release ; echo "${VERSION_ID}")"
                DISTRO_VERSION_MAJOR="$(cut -d. -f1 <<< "${DISTRO_VERSION}")"
            elif [[ -e /etc/redhat-release ]]; then
                # /etc/redhat-release covers RHEL
                DISTRO_NAME=rhel
                DISTRO_VERSION="$(lsb_release -s -r)"
                DISTRO_VERSION_MAJOR="$(cut -d. -f1 <<< "${DISTRO_VERSION}")"
            fi
            case "${DISTRO_NAME}" in
                ubuntu | linuxmint)
                    MONGODB_DOWNLOAD_URL="http://downloads.10gen.com/linux/mongodb-linux-$(uname -m)-enterprise-ubuntu${DISTRO_VERSION_MAJOR}04-5.0.3.tgz"
                ;;
                rhel)
                    case "${DISTRO_VERSION_MAJOR}" in
                        7)
                            MONGODB_DOWNLOAD_URL="https://downloads.mongodb.com/linux/mongodb-linux-x86_64-enterprise-rhel70-5.0.3.tgz"
                        ;;
                        *)
                            echo "Unsupported version of RHEL ${DISTRO_VERSION}"
                            exit 1
                        ;;
                    esac
                ;;
                *)
                    echo "Unsupported platform Linux ${DISTRO_NAME}"
                    exit 1
                ;;
            esac
        ;;
        *)
            echo "Unsupported platform ${target}"
            exit 1
        ;;
    esac
    export BAAS_PLATFORM
    # shellcheck source=/dev/null
    source "${baas_contents_file}"

    if [[ -z "${GOLANG_URL}" ]]; then
        echo " not defined in constants.sh file"
        exit_code=1
    fi
    if [[ -z "${STITCH_SUPPORT_LIB_URL}" ]]; then
        echo "STITCH_SUPPORT_LIB_URL not defined in constants.sh file"
        exit_code=1
    fi
    if [[ "${target}" == "Linux" && -z "${LIBMONGO_URL}" ]]; then
        echo " not defined in constants.sh file"
        exit_code=1
    fi
    if [[ "${target}" == "Darwin" && -z "${ASSISTED_AGG_URL}" ]]; then
        echo "ASSISTED_AGG_URL not defined in constants.sh file for Mac OS target"
        exit_code=1
    fi
    if [[ ${exit_code} -eq 1 ]]; then
        exit 1
    fi
}

# Allow path to CURL to be overloaded by an environment variable
CURL="${CURL:=$LAUNCHER curl}"

BASE_PATH="$(cd "$(dirname "$0")"; pwd)"

REALPATH="${BASE_PATH}/abspath.sh"

function usage()
{
    echo "Usage: install_baas.sh -w PATH [-b BRANCH] [-v] [-h]"
    echo -e "\t-w PATH\t\tPath to working dir"
    echo -e "\t-b BRANCH\tOptional branch or git spec of baas to checkout/build"
    echo -e "\t-v\t\tEnable verbose script debugging"
    echo -e "\t-h\t\tShow this usage summary and exit"
    # Default to 0 if exit code not provided
    exit "${1:0}"
}

WORK_PATH=
BAAS_VERSION=
VERBOSE=

while getopts "w:b:vh" opt; do
    case "${opt}" in
        w) WORK_PATH="$($REALPATH "${OPTARG}")";;
        b) BAAS_VERSION="${OPTARG}";;
        v) VERBOSE="yes"; set -o verbose; set -o xtrace;;
        h) usage 0;;
        *) usage 1;;
    esac
done

if [[ -z "${WORK_PATH}" ]]; then
    echo "Must specify working directory"
    usage 1
fi

# Check the mongodb and baas_server port availability first
MONGODB_PORT=26000
BAAS_PORT=9090

MONGODB_PORT_CHECK=$(lsof -P -i:${MONGODB_PORT} | grep "LISTEN" || true)
if [[ -n "${MONGODB_PORT_CHECK}" ]]; then
    echo "Error: mongodb port (${MONGODB_PORT}) is already in use"
    echo -e "${MONGODB_PORT_CHECK}"
    exit 1
fi

BAAS_PORT_CHECK=$(lsof -P -i:${BAAS_PORT} | grep "LISTEN" || true)
if [[ -n "${BAAS_PORT_CHECK}" ]]; then
    echo "Error: baas server port (${BAAS_PORT}) is already in use"
    echo -e "${BAAS_PORT_CHECK}"
    exit 1
fi

# Create and cd into the working directory
[[ -d ${WORK_PATH} ]] || mkdir -p "${WORK_PATH}"
pushd "${WORK_PATH}" > /dev/null
echo "Work path: ${WORK_PATH}"

# Set up some directory paths
BAAS_DIR="${WORK_PATH}/baas"
BAAS_DEPS_DIR="${WORK_PATH}/baas_dep_binaries"
NODE_BINARIES_DIR="${WORK_PATH}/node_binaries"
MONGO_BINARIES_DIR="${WORK_PATH}/mongodb-binaries"
MONGODB_PATH="${WORK_PATH}/mongodb-dbpath"

DYLIB_DIR="${BAAS_DIR}/etc/dylib"
DYLIB_LIB_DIR="${DYLIB_DIR}/lib"
TRANSPILER_DIR="${BAAS_DIR}/etc/transpiler"
LIBMONGO_DIR="${BAAS_DIR}/etc/libmongo"

# Define files for storing state
BAAS_SERVER_LOG="${WORK_PATH}/baas_server.log"
BAAS_READY_FILE="${WORK_PATH}/baas_ready"
BAAS_STOPPED_FILE="${WORK_PATH}/baas_stopped"
BAAS_PID_FILE="${WORK_PATH}/baas_server.pid"
MONGOD_PID_FILE="${WORK_PATH}/mongod.pid"
MONGOD_LOG="${MONGODB_PATH}/mongod.log"

# Delete the mongod working directory if it exists from a previous run
# Wait to create this directory until just before mongod is started
if [[ -d "${MONGODB_PATH}" ]]; then
    rm -rf "${MONGODB_PATH}"
fi

# Remove some files from a previous run if they exist
if [[ -f "${BAAS_SERVER_LOG}" ]]; then
    rm "${BAAS_SERVER_LOG}"
fi
if [[ -f "${BAAS_READY_FILE}" ]]; then
    rm "${BAAS_READY_FILE}"
fi
if [[ -f "${BAAS_STOPPED_FILE}" ]]; then
    rm "${BAAS_STOPPED_FILE}"
fi
if [[ -f "${BAAS_PID_FILE}" ]]; then
    rm "${BAAS_PID_FILE}"
fi
if [[ -f "${MONGOD_PID_FILE}" ]]; then
    rm "${MONGOD_PID_FILE}"
fi

# Set up the cleanup function that runs at exit and stops mongod and the baas server
function cleanup()
{
    # The baas server is being stopped (or never started), create a 'baas_stopped' file
    touch "${BAAS_STOPPED_FILE}"

    baas_pid=""
    mongod_pid=""
    if [[ -f "${BAAS_PID_FILE}" ]]; then
        baas_pid="$(< "${BAAS_PID_FILE}")"
    fi

    if [[ -f "${MONGOD_PID_FILE}" ]]; then
        mongod_pid="$(< "${MONGOD_PID_FILE}")"
    fi

    if [[ -n "${baas_pid}" ]]; then
        echo "Stopping baas ${baas_pid}"
        kill "${baas_pid}"
        echo "Waiting for baas to stop"
        wait "${baas_pid}"
    fi

    if [[ -n "${mongod_pid}" ]]; then
        echo "Killing mongod ${mongod_pid}"
        kill "${mongod_pid}"
        echo "Waiting for processes to exit"
        wait
    fi
}

trap "exit" INT TERM ERR
trap 'cleanup $?' EXIT

setup_target_dependencies

# Create the <work_path>/baas_dep_binaries/ directory
[[ -d "${BAAS_DEPS_DIR}" ]] || mkdir -p "${BAAS_DEPS_DIR}"
pathadd "${BAAS_DEPS_DIR}"

# Download jq (used for parsing json files) if it's not found
if [[ ! -x "${BAAS_DEPS_DIR}/jq" ]]; then
    pushd "${BAAS_DEPS_DIR}" > /dev/null
    which jq || (${CURL} -LsS "${JQ_DOWNLOAD_URL}" > jq && chmod +x jq)
    popd > /dev/null  # baas_dep_binaries
fi
echo "jq version: $(jq --version)"

# Fix incompatible github path that was changed in a BAAS dependency
git config --global url."git@github.com:".insteadOf "https://github.com/"
export GOPRIVATE="github.com/10gen/*"

# If a baas branch or commit version was not provided, retrieve the latest release version
if [[ -z "${BAAS_VERSION}" ]]; then
    BAAS_VERSION=$(${CURL} -LsS "https://realm.mongodb.com/api/private/v1.0/version" | jq -r '.backend.git_hash')
fi

# Clone the baas repo and check out the specified version
if [[ ! -d "${BAAS_DIR}/.git" ]]; then
#    git clone git@github.com:10gen/baas.git "${BAAS_DIR}"
    git clone git@github.com:mpobrien/stitch.git "${BAAS_DIR}"
    pushd "${BAAS_DIR}" > /dev/null
else
    pushd "${BAAS_DIR}" > /dev/null
    git fetch
fi

echo "Checking out baas version '${BAAS_VERSION}'"
git checkout "${BAAS_VERSION}"
echo "Using baas commit: $(git rev-parse HEAD)"
popd > /dev/null  # baas

setup_baas_dependencies "${BAAS_DIR}"

echo "Installing node and go to build baas and its dependencies"

# Create the <work_path>/node_binaries/ directory
[[ -d "${NODE_BINARIES_DIR}" ]] || mkdir -p "${NODE_BINARIES_DIR}"
# Download node if it's not found
if [[ ! -x "${NODE_BINARIES_DIR}/bin/node" ]]; then
    pushd "${NODE_BINARIES_DIR}" > /dev/null
    ${CURL} -LsS "${NODE_URL}" | tar -xz --strip-components=1
    popd > /dev/null  # node_binaries
fi
pathadd "${NODE_BINARIES_DIR}/bin"
echo "Node version: $(node --version)"

# Download go if it's not found and set up the GOROOT for building/running baas
[[ -x ${WORK_PATH}/go/bin/go ]] || (${CURL} -sL "${GOLANG_URL}" | tar -xz)
export GOROOT="${WORK_PATH}/go"
pathadd "${WORK_PATH}/go/bin"
echo "Go version: $(go version)"

# Copy or download and extract the baas support archive if it's not found
if [[ ! -d "${DYLIB_DIR}" ]]; then
    echo "Downloading baas support library"
    echo "path: ${DYLIB_DIR}"
    mkdir -p "${DYLIB_DIR}"
    pushd "${DYLIB_DIR}" > /dev/null
    ${CURL} -LsS "${STITCH_SUPPORT_LIB_URL}" | tar -xz --strip-components=1
    popd > /dev/null  # baas/etc/dylib
fi
export LD_LIBRARY_PATH="${DYLIB_LIB_DIR}"
export DYLD_LIBRARY_PATH="${DYLIB_LIB_DIR}"

# Create the libmongo/ directory
[[ -d "${LIBMONGO_DIR}" ]] || mkdir -p "${LIBMONGO_DIR}"
pathadd "${LIBMONGO_DIR}"

# Copy or download the assisted agg library as libmongo.so (for Linux) if it's not found
LIBMONGO_LIB="${LIBMONGO_DIR}/libmongo.so"
if [[ ! -x "${LIBMONGO_LIB}" && -n "${LIBMONGO_URL}" ]]; then
    echo "Downloading assisted agg library (libmongo.so)"
    echo "path: ${LIBMONGO_LIB}"
    pushd "${LIBMONGO_DIR}" > /dev/null
    ${CURL} -LsS "${LIBMONGO_URL}" > "${LIBMONGO_LIB}"
    chmod 755 "${LIBMONGO_LIB}"
    popd > /dev/null  # etc/libmongo
fi

# Download the assisted agg library as assisted_agg (for MacOS) if it's not found
ASSISTED_AGG_LIB="${LIBMONGO_DIR}/assisted_agg"
if [[ ! -x "${ASSISTED_AGG_LIB}" && -n "${ASSISTED_AGG_URL}" ]]; then
    echo "Downloading assisted agg binary (assisted_agg)"
    echo "path: ${ASSISTED_AGG_LIB}"
    pushd "${LIBMONGO_DIR}" > /dev/null
    ${CURL} -LsS "${ASSISTED_AGG_URL}" > "${ASSISTED_AGG_LIB}"
    chmod 755 "${ASSISTED_AGG_LIB}"
    popd > /dev/null  # etc/libmongo
fi

# Download yarn if it's not found
YARN="${WORK_PATH}/yarn/bin/yarn"
if [[ ! -x "${YARN}" ]]; then
    echo "Getting yarn"
    mkdir -p yarn && pushd yarn > /dev/null
    ${CURL} -LsS https://yarnpkg.com/latest.tar.gz | tar -xz --strip-components=1
    popd > /dev/null  # yarn
    mkdir "${WORK_PATH}/yarn_cache"
fi

# Use yarn to build the transpiler for the baas server
BAAS_TRANSPILER="${BAAS_DEPS_DIR}/transpiler"
if [[ ! -x "${BAAS_TRANSPILER}" ]]; then
    echo "Building transpiler"
    pushd "${TRANSPILER_DIR}" > /dev/null
    ${YARN} --non-interactive --silent --cache-folder "${WORK_PATH}/yarn_cache"
    ${YARN} build --cache-folder "${WORK_PATH}/yarn_cache" --non-interactive --silent
    popd > /dev/null  # baas/etc/transpiler
    ln -s "${TRANSPILER_DIR}/bin/transpiler" "${BAAS_TRANSPILER}"
fi

# Download mongod (daemon) and mongosh (shell) binaries
if [ ! -x "${MONGO_BINARIES_DIR}/bin/mongod" ]; then
    echo "Downloading mongodb"
    ${CURL} -sLS "${MONGODB_DOWNLOAD_URL}" --output mongodb-binaries.tgz

    tar -xzf mongodb-binaries.tgz
    rm mongodb-binaries.tgz
    mv mongodb* mongodb-binaries
    chmod +x "${MONGO_BINARIES_DIR}/bin"/*
fi

if [[ -n "${MONGOSH_DOWNLOAD_URL}" ]] && [[ ! -x "${MONGO_BINARIES_DIR}/bin/mongosh" ]]; then
    echo "Downloading mongosh"
    ${CURL} -sLS "${MONGOSH_DOWNLOAD_URL}" --output mongosh-binaries.zip
    unzip -jnqq mongosh-binaries.zip '*/bin/*' -d "${MONGO_BINARIES_DIR}/bin/"
    rm mongosh-binaries.zip
fi

[[ -n "${MONGOSH_DOWNLOAD_URL}" ]] && MONGOSH="mongosh" || MONGOSH="mongo"


# Start mongod on port 26000 and listening on all network interfaces
echo "Starting mongodb"

# Increase the maximum number of open file descriptors (needed by mongod)
ulimit -n 32000

# The mongod working files will be stored in the <work_path>/mongodb_dbpath directory
mkdir -p "${MONGODB_PATH}"

"${MONGO_BINARIES_DIR}/bin/mongod" \
    --replSet rs \
    --bind_ip_all \
    --port 26000 \
    --oplogMinRetentionHours 1.0 \
    --logpath "${MONGOD_LOG}" \
    --dbpath "${MONGODB_PATH}/" \
    --pidfilepath "${MONGOD_PID_FILE}" &


# Wait for mongod to start (up to 40 secs) while attempting to initialize the replica set
echo "Initializing replica set"

RETRY_COUNT=10
WAIT_COUNTER=0
WAIT_START=$(date -u +'%s')

until "${MONGO_BINARIES_DIR}/bin/${MONGOSH}" mongodb://localhost:26000/auth --eval 'try { rs.initiate(); } catch (e) { if (e.codeName != "AlreadyInitialized") { throw e; } }' > /dev/null
do
    ((++WAIT_COUNTER))
    if [[ -z "$(pgrep mongod)" ]]; then
        secs_spent_waiting=$(($(date -u +'%s') - WAIT_START))
        echo "Mongodb process has terminated after ${secs_spent_waiting} seconds"
        exit 1
    elif [[ ${WAIT_COUNTER} -ge ${RETRY_COUNT} ]]; then
        secs_spent_waiting=$(($(date -u +'%s') - WAIT_START))
        echo "Timed out after waiting ${secs_spent_waiting} seconds for mongod to start"
        exit 1
    fi

    sleep 2
done

# Add the baas user to mongod so it can connect to and access the database
pushd "${BAAS_DIR}" > /dev/null
echo "Adding baas user"
go run -exec="env LD_LIBRARY_PATH=${LD_LIBRARY_PATH} DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}" cmd/auth/user.go \
    addUser \
    -domainID 000000000000000000000000 \
    -mongoURI mongodb://localhost:26000 \
    -salt 'DQOWene1723baqD!_@#'\
    -id "unique_user@domain.com" \
    -password "password"

# Build the baas server using go
[[ -d tmp ]] || mkdir tmp
echo "Building baas app server"
[[ -f "${BAAS_PID_FILE}" ]] && rm "${BAAS_PID_FILE}"
go build -o "${WORK_PATH}/baas_server" cmd/server/main.go

# Based on https://github.com/10gen/baas/pull/10665
# Add a version to the schema change history store so that the drop optimization does not take place
# This caused issues with this test failing once app deletions starting being done asynchronously
echo "Adding fake appid to skip baas server drop optimization"
"${MONGO_BINARIES_DIR}/bin/${MONGOSH}"  --quiet mongodb://localhost:26000/__realm_sync "${BASE_PATH}/add_fake_appid.js"

# Start the baas server on port *:9090 with the provided config JSON files
echo "Starting baas app server"

"${WORK_PATH}/baas_server" \
    --configFile=etc/configs/test_config.json --configFile="${BASE_PATH}/config_overrides.json" > "${BAAS_SERVER_LOG}" 2>&1 &
echo $! > "${BAAS_PID_FILE}"

WAIT_BAAS_OPTS=()
if [[ -n "${VERBOSE}" ]]; then
    WAIT_BAAS_OPTS=("-v")
fi

"${BASE_PATH}/wait_for_baas.sh" "${WAIT_BAAS_OPTS[@]}" -w "${WORK_PATH}"

# Create the admin user and set up the allowed roles
echo "Adding roles to admin user"
${CURL} 'http://localhost:9090/api/admin/v3.0/auth/providers/local-userpass/login' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  --silent \
  --fail \
  --output /dev/null \
  --data '{"username":"unique_user@domain.com","password":"password"}'

"${MONGO_BINARIES_DIR}/bin/${MONGOSH}"  --quiet mongodb://localhost:26000/auth "${BASE_PATH}/add_admin_roles.js"

# All done! the 'baas_ready' file indicates the baas server has finished initializing
touch "${BAAS_READY_FILE}"

echo "---------------------------------------------"
echo "Baas server ready"
echo "---------------------------------------------"
wait
popd > /dev/null  # baas