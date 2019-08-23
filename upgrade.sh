#!/usr/bin/env bash

readonly DETECTED_PUID=${SUDO_UID:-$UID}
readonly DETECTED_UNAME=$(id -un "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_PGID=$(id -g "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_UGROUP=$(id -gn "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_HOMEDIR=$(eval echo "~${DETECTED_UNAME}" 2> /dev/null || true)
readonly FIRSTRUN_DIR="${DETECTED_HOMEDIR}/OpenFLIXR2.FirstRun"
readonly FIRSTRUN_DATA_DIR="${DETECTED_HOMEDIR}/.FirstRun"
readonly FIRSTRUN_LOG_DIR="${FIRSTRUN_DATA_DIR}/logs"

# Colors
# https://misc.flogisoft.com/bash/tip_colors_and_formatting
readonly BLU='\e[34m'
readonly GRN='\e[32m'
readonly RED='\e[31m'
readonly YLW='\e[33m'
readonly NC='\e[0m'

# Log Functions
readonly LOG_FILE="${FIRSTRUN_LOG_DIR}/upgrade.log"
sudo chown "${DETECTED_PUID:-$DETECTED_UNAME}":"${DETECTED_PGID:-$DETECTED_UGROUP}" "${LOG_FILE}" > /dev/null 2>&1 || true # This line should always use sudo
log() {
    if [[ -v DEBUG && $DEBUG == 1 ]] || [[ -v VERBOSE && $VERBOSE == 1 ]] || [[ -v DEVMODE && $DEVMODE == 1 ]]; then
        echo -e "${NC}$(date +"%F %T") ${BLU}[LOG]${NC}        $*${NC}" | tee -a "${LOG_FILE}";
    else
        echo -e "${NC}$(date +"%F %T") ${BLU}[LOG]${NC}        $*${NC}" | tee -a "${LOG_FILE}" > /dev/null;
    fi
}
info() { echo -e "${NC}$(date +"%F %T") ${BLU}[INFO]${NC}       $*${NC}" | tee -a "${LOG_FILE}"; }
warning() { echo -e "${NC}$(date +"%F %T") ${YLW}[WARNING]${NC}    $*${NC}" | tee -a "${LOG_FILE}"; }
error() { echo -e "${NC}$(date +"%F %T") ${RED}[ERROR]${NC}      $*${NC}" | tee -a "${LOG_FILE}"; }
fatal() {
    echo -e "${NC}$(date +"%F %T") ${RED}[FATAL]${NC}      $*${NC}" | tee -a "${LOG_FILE}"
    exit 1
}
debug() {
    if [[ -v DEBUG && $DEBUG == 1 ]] || [[ -v VERBOSE && $VERBOSE == 1 ]] || [[ -v DEVMODE && $DEVMODE == 1 ]]; then
        echo -e "${NC}$(date +"%F %T") ${GRN}[DEBUG]${NC}      $*${NC}" | tee -a "${LOG_FILE}"
    fi
}

# Cleanup Function
cleanup() {
    log "Removing lock file"
    rm "${FIRSTRUN_DATA_DIR}/upgrade.lock"
}

exec 2> >(tee -a "${LOG_FILE}")

if [[ ${DETECTED_PUID} == "0" ]] || [[ ${DETECTED_HOMEDIR} == "/root" ]]; then
    error "Running as root is not supported. Please run as a standard user with sudo."
    exit 1
fi

if [[ -f "${FIRSTRUN_DATA_DIR}/.config" ]]; then
    source "${FIRSTRUN_DATA_DIR}/.config"
    log "DEV_BRANCH='${DEV_BRANCH:-}'"
    log "FIRSTRUN_BRANCH='${FIRSTRUN_BRANCH:-}'"
    log "SETUP_BRANCH='${SETUP_BRANCH:-}'"
    log "DEV_MODE='${DEV_MODE:-}'"
fi

if [[ ${EUID} -ne 0 ]]; then
    log "Re-running upgrade.sh with sudo"
    exec sudo bash "${FIRSTRUN_DIR}/upgrade.sh"
fi

if [[ ! -d "${FIRSTRUN_DATA_DIR}" ]]; then
    mkdir -p "${FIRSTRUN_DATA_DIR}"
fi
if { set -C; 2>/dev/null > "${FIRSTRUN_DATA_DIR}/upgrade.lock"; }; then
    trap 'cleanup' 0 1 2 3 6 14 15 INT
else
    echo "FirstRun Upgrade already running. If this is in error, you may remove the file by running 'rm ${FIRSTRUN_DATA_DIR}/upgrade.lock'"
    exit
fi

if [[ ${DEV_BRANCH:-} == "development" ]]; then
    if [[ ${FIRSTRUN_BRANCH:-} == "" ]]; then
        warning "FIRSTRUN_BRANCH not set. Defaulting to master"
    else
        info "FIRSTRUN_BRANCH is ${FIRSTRUN_BRANCH}"
    fi
    if [[ ${SETUP_BRANCH:-} == "" ]]; then
        warning "SETUP_BRANCH not set. Defaulting to origin/master"
    else
        info "SETUP_BRANCH is ${SETUP_BRANCH}"
    fi
fi

info " ------ Starting FirstRun Upgrade ------"
info "Getting latest for 'setupopenflixr'"
if [[ ! -d /opt/OpenFLIXR2.SetupScript/.git ]] && [[ ! -d /opt/OpenFLIXR2.SetupScript/.scripts ]]; then
    if [[ -d /opt/OpenFLIXR2.SetupScript ]]; then
        rm -r /opt/OpenFLIXR2.SetupScript/
    fi
    git clone https://github.com/openflixr/OpenFLIXR2.SetupScript /opt/OpenFLIXR2.SetupScript
    chown -R openflixr:openflixr /opt/OpenFLIXR2.SetupScript || fatal "Failed to set permissions on '/opt/OpenFLIXR2.SetupScript'"
else
    chown -R openflixr:openflixr /opt/OpenFLIXR2.SetupScript || fatal "Failed to set permissions on '/opt/OpenFLIXR2.SetupScript'"
fi

if [[ -d /opt/OpenFLIXR2.SetupScript/.git ]] && [[ -d /opt/OpenFLIXR2.SetupScript/.scripts ]]; then
    cd "/opt/OpenFLIXR2.SetupScript/" || fatal "Failed to change to '/opt/OpenFLIXR2.SetupScript/' directory."
    info "  Fetching recent changes from git."
    git fetch > /dev/null 2>&1 || fatal "Failed to fetch recent changes from git."
    GH_COMMIT=$(git rev-parse --short ${SETUP_BRANCH:-origin/master})
    info "  Updating OpenFLIXR2 Setup Script to '${GH_COMMIT}' on '${SETUP_BRANCH:-origin/master}'."
    git reset --hard "${SETUP_BRANCH:-origin/master}" > /dev/null 2>&1 || fatal "Failed to reset to '${SETUP_BRANCH:-origin/master}'."
    git pull > /dev/null 2>&1 || fatal "Failed to pull recent changes from git."
    git for-each-ref --format '%(refname:short)' refs/heads | grep -v master | xargs git branch -D > /dev/null 2>&1 || true
    chmod +x "/opt/OpenFLIXR2.SetupScript/main.sh" > /dev/null 2>&1 || fatal "OpenFLIXR2 Setup Script must be executable."
    info "  OpenFLIXR2 Setup Script has been updated to '${GH_COMMIT}' on '${SETUP_BRANCH:-origin/master}'"
else
    fatal "- Something went wrong getting 'setupopenflixr'"
fi
if [[ ${DEV_MODE:-} == "local" && -d "${DETECTED_HOMEDIR}/OpenFLIXR2.SetupScript/" ]]; then
    cp -r "${DETECTED_HOMEDIR}/OpenFLIXR2.SetupScript/main.sh" "/opt/OpenFLIXR2.SetupScript/"
    cp -r "${DETECTED_HOMEDIR}/OpenFLIXR2.SetupScript/.scripts" "/opt/OpenFLIXR2.SetupScript/"
fi
info "- Done"

info "Fixing setupopenflixr symlink"
bash /opt/OpenFLIXR2.SetupScript/main.sh -s

info "Bypassing pi-hole"
sed -i "s#nameserver.*#nameserver 8.8.8.8#g" "/etc/resolv.conf" 2> /dev/null

info "- Done"

if [[ ! -f "/etc/sudoers.d/firstrun" ]]; then
    info "Temporarily bypassing password for sudo so this will run on reboot"
    echo "openflixr ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/firstrun" || fatal "Unable to add"
    info "- Done"
else
    log "/etc/sudoers.d/firstrun already exists"
fi

setupopenflixr --no-log-submission -p uptime || exit
setupopenflixr --no-log-submission -p process_check || exit
info "Putting some fixes in place..."
setupopenflixr --no-log-submission -f sources
info "Checking that Apt Update works"
apt-get -y update > /dev/null || fatal "Apt Update failed!"
info "- Success!"
info "Fixing nginx"
if [[ -f "/etc/nginx/sites-enabled/reverse" ]]; then
    sudo sed -i 's/listen 443 ssl.*/#listen 443 ssl http2;  #ssl port config/g' "/etc/nginx/sites-enabled/reverse"
fi
info "- Done!"
setupopenflixr --no-log-submission -f updater
setupopenflixr --no-log-submission -f mono
setupopenflixr --no-log-submission -f redis
setupopenflixr --no-log-submission -f php
log "Checking DNS"
setupopenflixr --no-log-submission -p dns_check
setupopenflixr --no-log-submission -p ready_check || exit
log "System ready!"
log "Preparing for upgrade"
setupopenflixr --no-log-submission -p prepare_upgrade
log "Running upgrade..."
setupopenflixr --no-log-submission -p upgrade
