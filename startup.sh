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
        echo "Running FirstRun Upgrade script"
        echo "openflixr" | sudo -S bash "${FIRSTRUN_DIR}/upgrade.sh"
    fi
else
    if [[ ! -n "$(command -v screen)" ]]; then
        echo "openflixr" | sudo -S bash "${FIRSTRUN_DIR}/upgrade.sh"
    fi
    echo "Attempting to create and connect to screen session 'openflixr_setup'."
    if ! screen -list | grep -q "openflixr_setup"; then
        echo "Creating Screen session..."
        screen -dmS openflixr_setup
    fi
    echo "Connecting Screen session..."
    screen -x -R openflixr_setup
fi
