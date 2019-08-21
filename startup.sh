#!/usr/bin/env bash

readonly DETECTED_PUID=${SUDO_UID:-$UID}
readonly DETECTED_UNAME=$(id -un "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_PGID=$(id -g "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_UGROUP=$(id -gn "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_HOMEDIR=$(eval echo "~${DETECTED_UNAME}" 2> /dev/null || true)
readonly FIRSTRUN_DIR="${DETECTED_HOMEDIR}/OpenFLIXR2.FirstRun"
readonly FIRSTRUN_DATA_DIR="${DETECTED_HOMEDIR}/.FirstRun"
readonly FIRSTRUN_LOG_DIR="${FIRSTRUN_DATA_DIR}/logs"

if [[ ${TERM:0:6} == "screen" ]]; then
    SCREEN_SESSION_NAME=$(echo $STY | cut -d '.' -f 2)
    if [[ ${SCREEN_SESSION_NAME} == "openflixr_setup" ]]; then
        info "Getting latest for 'OpenFLIXR2.FirstRun'"
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
        echo "Running FirstRun Upgrade script"
        exec sudo bash "${FIRSTRUN_DIR}/upgrade.sh"
    fi
else
    echo "Attempting to create and connect to screen session 'openflixr_setup'."
    if ! screen -list | grep -q "openflixr_setup"; then
        screen -dmS openflixr_setup
    fi
    screen -x -R openflixr_setup -t openflixr_setup
fi
