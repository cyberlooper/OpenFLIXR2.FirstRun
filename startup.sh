#!/usr/bin/env bash

readonly DETECTED_PUID=${SUDO_UID:-$UID}
readonly DETECTED_UNAME=$(id -un "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_PGID=$(id -g "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_UGROUP=$(id -gn "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_HOMEDIR=$(eval echo "~${DETECTED_UNAME}" 2> /dev/null || true)
readonly FIRSTRUN_DIR="${DETECTED_HOMEDIR}/OpenFLIXR2.FirstRun"
readonly FIRSTRUN_DATA_DIR="${DETECTED_HOMEDIR}/.FirstRun"

if [[ ${TERM:0:6} == "screen" ]]; then
    SCREEN_SESSION_NAME=$(echo $STY | cut -d '.' -f 2)
    if [[ ${SCREEN_SESSION_NAME} == "openflixr_setup" ]]; then
        echo "Running FirstRun startup script"
        if [[ -f "${FIRSTRUN_DATA_DIR}/.config" ]]; then
            source "${FIRSTRUN_DATA_DIR}/.config"
        fi
        echo "Running FirstRun Upgrade script"
        exec sudo "${FIRSTRUN_DIR}/upgrade.sh"
    fi
else
    echo "Attempting to create and connect to screen session 'openflixr_setup'."
    if ! screen -list | grep -q "openflixr_setup"; then
        screen -dmS openflixr_setup
    fi
    screen -x -R openflixr_setup -t openflixr_setup
fi
