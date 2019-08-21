#!/usr/bin/env bash

readonly DETECTED_PUID=${SUDO_UID:-$UID}
readonly DETECTED_UNAME=$(id -un "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_PGID=$(id -g "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_UGROUP=$(id -gn "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_HOMEDIR=$(eval echo "~${DETECTED_UNAME}" 2> /dev/null || true)
readonly FIRSTRUN_DIR="${DETECTED_HOMEDIR}/OpenFLIXR2.FirstRun"
readonly FIRSTRUN_DATA_DIR="${DETECTED_HOMEDIR}/.FirstRun"
readonly FIRSTRUN_LOG_DIR="${FIRSTRUN_DATA_DIR}/logs"

if [[ ! -d "${FIRSTRUN_LOG_DIR}" ]]; then
    mkdir -p "${FIRSTRUN_LOG_DIR}"
fi

readonly LOG_FILE="${FIRSTRUN_LOG_DIR}/run_me.log"
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

if [[ ${DETECTED_PUID} == "0" ]] || [[ ${DETECTED_HOMEDIR} == "/root" ]]; then
    error "Running as root is not supported. Please run as a standard user with sudo."
    exit 1
fi

if [[ ${TERM:0:6} != "screen" ]]; then
    if [[ ! -n "$(command -v screen)" ]]; then
        warning "Screen needs to be installed..."
        echo "openflixr" | sudo -S apt-get -y install screen
    fi
    if [[ -f "${PRECHECK_DIR}/precheck.config" ]]; then
        source "${PRECHECK_DIR}/precheck.config"
        log "DEV_BRANCH='${DEV_BRANCH:-}'"
        log "FIRSTRUN_BRANCH='${FIRSTRUN_BRANCH:-}'"
        log "SETUP_BRANCH='${SETUP_BRANCH:-}'"
        log "DEV_MODE='${DEV_MODE:-}'"
    fi
    info "Getting latest for 'OpenFLIXR2.FirstRun'"
    if [[ ! -d "${FIRSTRUN_DIR}" ]]; then
        git clone https://github.com/openflixr/OpenFLIXR2.FirstRun.git "${FIRSTRUN_DIR}"
    fi

    if [[ -d "${FIRSTRUN_DIR}/.git" ]]; then
        cd "${FIRSTRUN_DIR}" || fatal "Failed to change to '${FIRSTRUN_DIR}' directory."
        info "  Fetching recent changes from git."
        git fetch > /dev/null 2>&1 || fatal "Failed to fetch recent changes from git."
        GH_COMMIT=$(git rev-parse --short ${FIRSTRUN_BRANCH:-origin/master})
        info "  Updating OpenFLIXR2 FirstRun Script to '${GH_COMMIT}' on '${FIRSTRUN_BRANCH:-origin/master}'."
        git reset --hard "${FIRSTRUN_BRANCH:-origin/master}" > /dev/null 2>&1 || fatal "Failed to reset to '${FIRSTRUN_BRANCH:-origin/master}'."
        git pull > /dev/null 2>&1 || fatal "Failed to pull recent changes from git."
        git for-each-ref --format '%(refname:short)' refs/heads | grep -v master | xargs git branch -D > /dev/null 2>&1 || true
        chmod +x "${FIRSTRUN_DIR}/run_me.sh" > /dev/null 2>&1 || fatal "OpenFLIXR2 FirstRun Script must be executable."
        info "  OpenFLIXR2 FirstRun Script has been updated to '${GH_COMMIT}' on '${FIRSTRUN_BRANCH:-origin/master}'"
    else
        fatal "- Something went wrong getting 'OpenFLIXR2.FirstRun'"
    fi
    if [[ $(grep -c "bash ${FIRSTRUN_DIR}/startup.sh" "${DETECTED_HOMEDIR}/.bashrc") == 0 ]]; then
        info "Adding FirstRun startup script to .profile to run on boot until this is all done..."
        echo "" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "if [[ -f ${FIRSTRUN_DIR}/startup.sh ]]; then" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "    bash ${FIRSTRUN_DIR}/startup.sh" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "fi" >> "${DETECTED_HOMEDIR}/.bashrc"
        info "- Done"
    fi

    echo "Attempting to create and connect to screen session 'openflixr_setup'."
    if ! screen -list | grep -q "openflixr_setup"; then
        screen -dmS openflixr_setup
    fi
    screen -x -R openflixr_setup -t openflixr_setup
fi
