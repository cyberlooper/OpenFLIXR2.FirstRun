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

if [[ ! -d "${FIRSTRUN_LOG_DIR}" ]]; then
    echo "Creating log directory"
    mkdir -p "${FIRSTRUN_LOG_DIR}"
fi

readonly LOG_FILE="${FIRSTRUN_LOG_DIR}/run_me.log"
echo "openflixr" | sudo -S chown "${DETECTED_PUID:-$DETECTED_UNAME}":"${DETECTED_PGID:-$DETECTED_UGROUP}" "${LOG_FILE}" > /dev/null 2>&1 || true # This line should always use sudo
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
    if [[ -f "${FIRSTRUN_DATA_DIR}/.config" ]]; then
        source "${FIRSTRUN_DATA_DIR}/.config"
        log "DEV_BRANCH='${DEV_BRANCH:-}'"
        log "FIRSTRUN_BRANCH='${FIRSTRUN_BRANCH:-}'"
        log "SETUP_BRANCH='${SETUP_BRANCH:-}'"
        log "DEV_MODE='${DEV_MODE:-}'"

        warn "!!!! This script is no longer maintained !!!!"
        echo "This script is no longer maintained and looking for a maintainer."
        echo "If you are interested in maintaining this script, please post a message on the OpenFLIXR Discord server."
        echo "You may continue using OpenFLIXR as is but support will be limited until a maintainer is found to update the code, etc."
        read -rp "Press enter to continue or Ctrl+c/Cmd+c to cancel" -t 60

        if [[ ${FIRSTRUN_BRANCH:-} != "" ]]; then
            CHECK_FIRSTRUN_BRANCH=$(git ls-remote --heads https://github.com/cyberlooper/OpenFLIXR2.FirstRun.git ${FIRSTRUN_BRANCH/"origin/"/} | wc -l)
            if [[ ${CHECK_FIRSTRUN_BRANCH} -eq 0 ]]; then
                warn "'${FIRSTRUN_BRANCH}' does not exist for OpenFLIXR2.FirstRun. Defaulting to 'origin/master'"
                FIRSTRUN_BRANCH=""
            fi
        fi

        if [[ ${SETUP_BRANCH:-} != "" ]]; then
            CHECK_SETUP_BRANCH=$(git ls-remote --heads https://github.com/cyberlooper/OpenFLIXR2.SetupScript ${SETUP_BRANCH/"origin/"/} | wc -l)
            if [[ ${SETUP_BRANCH} -eq 0 ]]; then
                warn "'${SETUP_BRANCH}' does not exist for OpenFLIXR2.SetupScript. Defaulting to 'origin/master'"
                SETUP_BRANCH=""
            fi
        fi
    fi
    info "Getting latest for 'OpenFLIXR2.FirstRun'"
    if [[ ! -d "${FIRSTRUN_DIR}" ]]; then
        git clone https://github.com/cyberlooper/OpenFLIXR2.FirstRun.git "${FIRSTRUN_DIR}"
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
        info "  OpenFLIXR2 FirstRun Script has been updated to '${GH_COMMIT}' on '${FIRSTRUN_BRANCH:-origin/master}'"
    else
        fatal "- Something went wrong getting 'OpenFLIXR2.FirstRun'"
    fi
    info "Getting latest for 'setupopenflixr'"
    if [[ ! -d /opt/OpenFLIXR2.SetupScript/ ]]; then
        echo "openflixr" | sudo -S git clone https://github.com/cyberlooper/OpenFLIXR2.SetupScript /opt/OpenFLIXR2.SetupScript
    fi
    info "  Setting permissions on '/opt/OpenFLIXR2.SetupScript'"
    echo "openflixr" | sudo -S chown -R openflixr:openflixr /opt/OpenFLIXR2.SetupScript || fatal "Failed to set permissions on '/opt/OpenFLIXR2.SetupScript'"

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

    if [[ $(grep -c "#firstrun-startup" "${DETECTED_HOMEDIR}/.bashrc") == 0 ]]; then
        info "Adding FirstRun startup script to .profile to run on boot until this is all done..."
        echo "" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "if [[ -f ${FIRSTRUN_DIR}/startup.sh ]]; then   #firstrun-startup" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "    bash ${FIRSTRUN_DIR}/startup.sh            #firstrun-startup" >> "${DETECTED_HOMEDIR}/.bashrc"
        echo "fi                                             #firstrun-startup" >> "${DETECTED_HOMEDIR}/.bashrc"
        info "- Done"
    fi

    info "Fixing setupopenflixr symlink"
    echo "openflixr" | sudo -S bash /opt/OpenFLIXR2.SetupScript/main.sh -s

    # info "Correcting unmet dependency"
    # bash ${FIRSTRUN_DIR}/ombi.sh

    info "Running startup script"
    bash ${FIRSTRUN_DIR}/startup.sh
fi