#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Usage Information
#/ Usage: bash run_openflixr_vm.sh [OPTION]
#/
#/  -h --help
#/      Show this usage information.
#/  -i --ip <IP.Address>
#/      Bypasses IP Detection by hostname for the IP provided.
#/  -l --log-level <level name>
#/      Turn on more detailed logging. <log level> should be replaced with one of the following:
#/      - FATAL
#/      - ERROR
#/      - WARN
#/      - NOTICE (default level)
#/      - INFO
#/      - DEBUG
#/      - TRACE
#/  -r --refresh-vm
#/      This will destroy your VM and recreate it. Use with caution.
#/  -t --test
#/      Run tests after the VM is ready.
#/

usage() {
    grep '^#/' "${SCRIPTNAME}" | cut -c4- || echo "Failed to display usage information."
    exit
}

# Command Line Arguments
readonly ARGS=("$@")

# Script Information
# https://stackoverflow.com/a/246128/1384186
get_scriptname() {
    local SOURCE
    local DIR
    SOURCE="${BASH_SOURCE[0]:-$0}" # https://stackoverflow.com/questions/35006457/choosing-between-0-and-bash-source
    while [[ -L ${SOURCE} ]]; do # resolve ${SOURCE} until the file is no longer a symlink
        DIR="$(cd -P "$(dirname "${SOURCE}")" > /dev/null && pwd)"
        SOURCE="$(readlink "${SOURCE}")"
        [[ ${SOURCE} != /* ]] && SOURCE="${DIR}/${SOURCE}" # if ${SOURCE} was a relative symlink, we need to resolve it relative to the path where the symlink file was located
    done
    echo "${SOURCE}"
}
readonly SCRIPTNAME="$(get_scriptname)"
readonly SCRIPTPATH="$(cd -P "$(dirname "${SCRIPTNAME}")" > /dev/null && pwd)"

# User/Group Information
readonly DETECTED_PUID=${SUDO_UID:-$UID}
readonly DETECTED_UNAME=$(id -un "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_PGID=$(id -g "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_UGROUP=$(id -gn "${DETECTED_PUID}" 2> /dev/null || true)
readonly DETECTED_HOMEDIR=$(eval echo "~${DETECTED_UNAME}" 2> /dev/null || true)

# Other Information
readonly DATA_DIR="${DETECTED_HOMEDIR}/OpenFLIXR"
readonly VM_NAME="OpenFLIXR"
readonly VM_USERNAME="openflixr"
readonly VM_PASSWORD="openflixr"
readonly VM_HOST="openflixr"
readonly RUNME_PID_FILE="${DETECTED_HOMEDIR}/OpenFLIXR/run_me.pid"

# Terminal Colors
if [[ ${CI:-} == true ]] || [[ -t 1 ]]; then
    readonly SCRIPTTERM=true
fi
tcolor() {
    if [[ -n ${SCRIPTTERM:-} ]]; then
        # http://linuxcommand.org/lc3_adv_tput.php
        local BF=${1:-}
        local CAP
        case ${BF} in
            [Bb]) CAP=setab ;;
            [Ff]) CAP=setaf ;;
            [Nn][Cc]) CAP=sgr0 ;;
            *) return ;;
        esac
        local COLOR_IN=${2:-}
        local VAL
        if [[ ${CAP} != "sgr0" ]]; then
            case ${COLOR_IN} in
                [Bb4]) VAL=4 ;; # Blue
                [Cc6]) VAL=6 ;; # Cyan
                [Gg2]) VAL=2 ;; # Green
                [Kk0]) VAL=0 ;; # Black
                [Mm5]) VAL=5 ;; # Magenta
                [Rr1]) VAL=1 ;; # Red
                [Ww7]) VAL=7 ;; # White
                [Yy3]) VAL=3 ;; # Yellow
                *) return ;;
            esac
        fi
        local COLOR_OUT
        if [[ $(tput colors) -ge 8 ]]; then
            COLOR_OUT=$(eval tput ${CAP:-} ${VAL:-})
        fi
        echo "${COLOR_OUT:-}"
    else
        return
    fi
}
declare -Agr B=(
    [B]=$(tcolor B B)
    [C]=$(tcolor B C)
    [G]=$(tcolor B G)
    [K]=$(tcolor B K)
    [M]=$(tcolor B M)
    [R]=$(tcolor B R)
    [W]=$(tcolor B W)
    [Y]=$(tcolor B Y)
)
declare -Agr F=(
    [B]=$(tcolor F B)
    [C]=$(tcolor F C)
    [G]=$(tcolor F G)
    [K]=$(tcolor F K)
    [M]=$(tcolor F M)
    [R]=$(tcolor F R)
    [W]=$(tcolor F W)
    [Y]=$(tcolor F Y)
)
readonly NC=$(tcolor NC)

# Log Levels
readonly FATAL=0
readonly ERROR=1
readonly WARN=2
readonly NOTICE=3
readonly INFO=4
readonly DEBUG=5
readonly TRACE=6

# Log Functions
if [[ ! -d "${DATA_DIR}" ]]; then
    mkdir -p "${DATA_DIR}"
fi

readonly LOG_FILE="${DATA_DIR}/${VM_NAME}.log"
echo "" > "${LOG_FILE}" # Truncate log file

log() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${DEBUG} ]]; then
        echo -e "${NC}$(date +"%F %T") ${BLU}[LOG]${NC}        $*${NC}" | tee -a "${LOG_FILE}"
    else
        echo -e "${NC}$(date +"%F %T") ${BLU}[LOG]${NC}        $*${NC}" | tee -a "${LOG_FILE}" > /dev/null
    fi
}
trace() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${TRACE} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[B]}[TRACE ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2
    fi;
}
debug() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${DEBUG} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[B]}[DEBUG ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2
    fi;
}
info() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${INFO} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[B]}[INFO  ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2
    fi;
}
notice() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${NOTICE} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[G]}[NOTICE]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2;
    fi;
}
warn() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${WARN} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[Y]}[WARN  ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2;
    fi;
}
error() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${ERROR} ]]; then
        echo -e "${NC}$(date +"%F %T") ${F[R]}[ERROR ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2;
    fi;
}
fatal() {
    if [[ ${LOG_LEVEL:-${NOTICE}} -ge ${FATAL} ]]; then
        echo -e "${NC}$(date +"%F %T") ${B[R]}${F[W]}[FATAL ]${NC}   $*${NC}" | tee -a "${LOG_FILE}" >&2
        exit 1
    fi;
}

# Root Check
root_check() {
    if [[ ${PROXMOX:-} != 1 ]] && [[ ${DETECTED_PUID} == "0" || ${DETECTED_HOMEDIR} == "/root" ]]; then
        fatal "Running as root is not supported. Please run as a standard user without sudo."
    fi
}

# Cleanup Function
cleanup() {
    if [[ ${CI:-} == true ]] && [[ ${TRAVIS:-} == true ]] && [[ ${TRAVIS_SECURE_ENV_VARS} == false ]]; then
        warn "TRAVIS_SECURE_ENV_VARS is false for Pull Requests from remote branches. Please retry failed builds!"
    fi
    if [[ -f "${RUNME_PID_FILE}" ]]; then
        RUNME_PID=$(cat "${RUNME_PID_FILE}")
        if [ -e /proc/${RUNME_PID} -a /proc/${RUNME_PID}/exe ]; then
            kill -9 ${RUNME_PID}
        fi
    fi
}
trap 'cleanup' 0 1 2 3 6 14 15

# Valid IP Check
valid_ip()
{
    local  ip=${1:-}
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}
# Google Drive File Download
function gdrive_download () {
  CONFIRM=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate "https://docs.google.com/uc?export=download&id=$1" -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')
  wget --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$CONFIRM&id=$1" -O $2
  rm -rf /tmp/cookies.txt
}

cmdline() {
    # http://www.kfirlavi.com/blog/2012/11/14/defensive-bash-programming/
    # http://kirk.webfinish.com/2009/10/bash-shell-script-to-use-getopts-with-gnu-style-long-positional-parameters/
    local ARG=
    local LOCAL_ARGS
    for ARG; do
        local DELIM=""
        case "${ARG}" in
            #translate --gnu-long-options to -g (short options)--backup) LOCAL_ARGS="${LOCAL_ARGS:-}-b " ;;
            --help) LOCAL_ARGS="${LOCAL_ARGS:-}-h " ;;
            --ip) LOCAL_ARGS="${LOCAL_ARGS:-}-i " ;;
            --log-level) LOCAL_ARGS="${LOCAL_ARGS:-}-l " ;;
            --refresh-vm) LOCAL_ARGS="${LOCAL_ARGS:-}-r " ;;
            --test) LOCAL_ARGS="${LOCAL_ARGS:-}-t " ;;
            #pass through anything else
            *)
                [[ ${ARG:0:1} == "-" ]] || DELIM='"'
                LOCAL_ARGS="${LOCAL_ARGS:-}${DELIM}${ARG}${DELIM} "
                ;;
        esac
    done

    #Reset the positional parameters to the short options
    eval set -- "${LOCAL_ARGS:-}"

    while getopts ":hi:l:rt:" OPTION; do
        case ${OPTION} in
            h)
                usage
                exit
                ;;
            i)
                if valid_ip "${OPTARG}"; then
                    VM_IP="${OPTARG}"
                else
                    fatal "'${OPTARG}' is not a valid IP address"
                fi
                ;;
            l)
                case ${OPTARG} in
                    "fatal" | "FATAL" | ${FATAL})
                        readonly LOG_LEVEL=${FATAL}
                        ;;
                    "error" | "ERROR" | ${ERROR})
                        readonly LOG_LEVEL=${ERROR}
                        ;;
                    "warn" | "WARN" | "warning" | "WARNING" | ${WARN})
                        readonly LOG_LEVEL=${WARN}
                        ;;
                    "notice" | "NOTICE" | ${NOTICE})
                        readonly LOG_LEVEL=${NOTICE}
                        ;;
                    "info" | "INFO" | ${INFO})
                        readonly LOG_LEVEL=${INFO}
                        ;;
                    "debug" | "DEBUG" | ${DEBUG})
                        readonly LOG_LEVEL=${DEBUG}
                        ;;
                    "trace" | "TRACE" | ${TRACE})
                        readonly LOG_LEVEL=${TRACE}
                        ;;
                    *)
                        fatal "Invalid LOG LEVEL option."
                        ;;
                esac
                ;;
            r)
                readonly REFESH_VM="Y"
                ;;
            t)
                readonly TEST_MODE=1
                readonly TEST_CONFIG="${OPTARG}"
                ;;
            :)
                case ${OPTARG} in
                    t)
                        readonly TEST_MODE=1
                        readonly TEST_CONFIG="${DATA_DIR}/test.config"
                        ;;
                    *)
                        fatal "${OPTARG} requires an option."
                        ;;
                esac
                ;;
            *)
                usage
                exit
                ;;
        esac
    done
    return 0
}

# Main Function
main() {
    if [[ -n "$(command -v pvesh)" && -n "$(command -v qm)" ]]; then
        readonly PROXMOX=1
    fi
    # Sudo Check
    if [[ ${PROXMOX:-} != 1 && ${EUID} -eq 0 ]]; then
        fatal "Running with sudo is not supported. Please run as a standard user WITHOUT sudo."
    fi
    # Screen Check
    if [[ ${TERM:0:6} == "screen" ]]; then
        fatal "Running this in a screen session doesn't work. Exit screen and try again."
    fi
    # Arch Check
    readonly ARCH=$(uname -m)
    if [[ ${ARCH} != "aarch64" ]] && [[ ${ARCH} != "armv7l" ]] && [[ ${ARCH} != "x86_64" ]]; then
        fatal "Unsupported architecture."
    fi
    # Terminal Check
    if [[ -n ${PS1:-} ]] || [[ ${-} == *"i"* ]]; then
        root_check
    fi
    if [[ ${CI:-} != true ]] && [[ ${TRAVIS:-} != true ]]; then
        root_check

        #Process args
        cmdline "${ARGS[@]:-}"
        #Check for test config
        if [[ ${LOG_LEVEL:-} == "" ]]; then
            readonly LOG_LEVEL=${NOTICE}
        fi
        if [[ -v TEST_MODE && ! -f "${TEST_CONFIG}" ]]; then
            fatal "${TEST_CONFIG} not found."
        fi
        # OVA Check
        if [[ -f "OpenFLIXR_2.0_VMware_VirtualBox.ova" ]]; then
            info "Moving OVA to '${DATA_DIR}/'"
            mv "OpenFLIXR_2.0_VMware_VirtualBox.ova" "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova"
        fi
        if [[ -f "/var/lib/vz/template/iso/OpenFLIXR_2.0_VMware_VirtualBox.iso" ]]; then
            info "Renmaing ISO to OVA and moving to '${DATA_DIR}/'"
            mv "/var/lib/vz/template/iso/OpenFLIXR_2.0_VMware_VirtualBox.iso" "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova"
        fi
        if [[ ! -f "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova" ]]; then
            notice "'${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova' not found. Attempting to download it for you..."
            gdrive_download "1Ooac-HFcSID4vSSy5Mmtu1c5dSsnlXtQ" "OpenFLIXR_2.0_VMware_VirtualBox.ova" || fatal "Unable to download 'OpenFLIXR_2.0_VMware_VirtualBox.ova' for you. Please manually download it and try again."
        fi
        if [[ ! -n "$(command -v sshpass)" ]]; then
            warn "sshpass is not installed but needed. Installing now."
            apt-get -y update 2>/dev/null || true
            apt-get -y install sshpass
        fi
        readonly test_start=$(date +%s)

        if [[ -n "$(command -v vboxmanage)" ]]; then
            HYPERVISOR="VIRTUALBOX"
        elif [[ -n "$(command -v pvesh)" ]]; then
            HYPERVISOR="PROXMOX"
        else
            HYPERVISOR=""
            warn "No supported hypervisor found. Skipping VM checks and refresh sections..."
        fi

        if [[ ${HYPERVISOR} != "" ]]; then
            notice "Checking for existing ${VM_NAME} VM via ${HYPERVISOR}."
            if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                VM_ERROR_CHECK=$(vboxmanage showvminfo ${VM_NAME} 2>&1 | grep -c "error: Could not find a registered machine named '${VM_NAME}'" || true)
                VM_NAME_CHECK=$(vboxmanage showvminfo ${VM_NAME} 2>&1 | grep -c "Name:" || true)
            elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                VM_ERROR_CHECK=0
                if [[ $(qm list | grep "${VM_NAME}" | wc -l) -gt 1 ]]; then
                    warning "More than one ${VM_NAME} VM running..."
                    while true; do
                        qm list | grep "OpenFLIXR" | awk '{$1=$1;print}'
                        read -p 'Enter the VM ID from the list above that you want to remove: ' VM_ID
                        if [[ $(qm status ${VM_ID} 2>/dev/null| wc -l) == 0 ]]; then
                            error "${VM_ID} is invalid. Please try again..."
                            echo "------------------------------------"
                        else
                            break
                        fi
                    done
                    VM_NAME_CHECK=1
                elif [[ $(qm list | grep -c "${VM_NAME}") == 1 ]]; then
                    VM_ID=$(qm list | grep "${VM_NAME}" | awk '{print $1}')
                    VM_NAME_CHECK=1
                else
                    VM_ERROR_CHECK=1
                    VM_NAME_CHECK=0
                fi
            fi
            if [[ $VM_ERROR_CHECK -eq 0 && $VM_NAME_CHECK -ge 1 ]] ; then
                info "${VM_NAME} found!"
                if [[ ${REFESH_VM:-} == "Y" ]]; then
                    if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                        warn "Refreshing ${VM_NAME}"
                    elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                        warn "Refreshing ${VM_NAME} with ID ${VM_ID}"
                    fi
                    if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                        info "Powering off ${VM_NAME}"
                        NET_MAC=""
                        vboxmanage controlvm ${VM_NAME} poweroff 2>/dev/null || true
                        VM_STOPPING=$(vboxmanage showvminfo "${VM_NAME}" | grep -c "stopping (since" || true)
                    elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                        info "Stopping ${VM_NAME} with ID ${VM_ID}"
                        NET_MAC=$(qm config ${VM_ID} | grep "net" | awk -F'=' '{print $2}' | awk -F',' '{print $1}' || true)
                        qm stop ${VM_ID}
                        VM_STOPPING=1
                    fi
                    if [[ ${VM_STOPPING} -eq 1 ]]; then
                        info "Waiting for ${VM_NAME} VM to power off..."
                        while true; do
                            if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                                VM_STOP_CHECK=$(vboxmanage showvminfo "${VM_NAME}" | grep -c "stopping (since" || true)
                            elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                                VM_STOP_CHECK=$(qm status ${VM_ID} | grep -c "running" || true)
                            fi
                            if [[ ${VM_STOP_CHECK} == 0 ]]; then
                                echo ""
                                break
                            fi
                            echo -n "."
                            sleep 15s
                        done
                        info "- Stopped"
                    fi
                    info "Deleting ${VM_NAME}"
                    if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                        vboxmanage unregistervm --delete ${VM_NAME}
                    elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                        qm destroy ${VM_ID}
                    fi
                    IMPORT_VM=1
                    sleep 5s
                else
                    info "Keeping current VM"
                fi
            elif [[ $VM_ERROR_CHECK -eq 1 && $VM_NAME_CHECK -ge 0 ]] ; then
                info "No VM found with name. Importing as a new VM"
                IMPORT_VM=1
            else
                fatal "Something didn't work right with the VM Checks..."
            fi # VM check

            if [[ ${IMPORT_VM:-} == "1" ]]; then
                notice "Importing ${VM_NAME}"
                if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                    VBoxManage import "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova" --vsys 0 --vmname ${VM_NAME} --cpus 6 --memory 6144 > ${LOG_FILE}
                    if [[ ${NET_MAC:-} != "" && "${NET_MAC}" =~ ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$ ]]; then
                        VBoxManage modifyvm ${VM_NAME} --macaddress1 "${NET_MAC}" > ${LOG_FILE}
                    elif [[ ${NET_MAC:-} != "" ]]; then
                        warning "Detected MAC address from previous VM invalid. MAC address won't be set for ${VM_NAME}"
                    fi
                    VBoxManage modifyvm ${VM_NAME} --vrde on > ${LOG_FILE}
                    VBoxManage storagectl ${VM_NAME} --name SATA --remove > ${LOG_FILE}
                elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                    info "Extracting OVA"
                    tar -xvf "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ova" -C "${DATA_DIR}" > /dev/null
                    if [[ ! -f "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ovf" ]]; then
                        error "Cannot find 'OpenFLIXR_2.0_VMware_VirtualBox.ovf' in '${DATA_DIR}/'"
                        EXTRACT_ERROR=1
                    fi
                    if [[ ! -f "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox-disk1.vmdk" ]]; then
                        error "Cannot find 'OpenFLIXR_2.0_VMware_VirtualBox-disk1.vmdk' in '${DATA_DIR}/'"
                        EXTRACT_ERROR=1
                    fi
                    if [[ ${EXTRACT_ERROR:-0} == 1 ]]; then
                        error "Your OVA is probably not the correct one - must be 'OpenFLIXR_2.0_VMware_VirtualBox.ova' found on the OpenFLIXR Wiki or Website."
                        fatal "Aborting..."
                    fi
                    if [[ ${VM_ID:-} == "" ]]; then
                        info "Getting ID for new VM"
                        VM_ID=$(pvesh get /cluster/nextid)
                    fi

                    info "Importing configuration from OVF."
                    warn "This will take several minutes, even after you see '(100.00/100%)'. Keep waiting."
                    qm importovf ${VM_ID} "${DATA_DIR}/OpenFLIXR_2.0_VMware_VirtualBox.ovf" local-lvm
                    info "Updating configuration"
                    info "Setting name to ${VM_NAME}"
                    qm set ${VM_ID} --name "${VM_NAME}"
                    info "Setting boot order to only disk"
                    qm set ${VM_ID} --boot c
                    info "Setting SCSI Controller to VirtIO SCSI"
                    qm set ${VM_ID} --scsihw virtio-scsi-pci
                    # info "Getting disk storage info"
                    # VM_DISK=$(qm config ${VM_ID} | grep "scsi0:" | awk -F' ' '{print $2}' | awk -F',' '{print $1}')
                    info "Updating disk information"
                    qm rescan --vmid ${VM_ID}
                    info "Getting network interface ID"
                    NODE_NAME=$(cat /etc/hostname)
                    NET_COUNT=$(pvesh get /nodes/${NODE_NAME}/network -type any_bridge --noborder --noheader | wc -l)
                    if [[ ${NET_COUNT} -eq 1 ]]; then
                        NET_ID=$(pvesh get /nodes/${NODE_NAME}/network -type any_bridge --noborder --noheader | awk -F' ' '{print $10}')
                    elif [[ ${NET_COUNT} -gt 1 ]]; then
                        warning "More than one network interface found..."
                        while true; do
                            pvesh get /nodes/${NODE_NAME}/network -type any_bridge --noborder --noheader | awk -F' ' '{print $10}'
                            read -p 'Enter the network interface ID from the list above that you want to use: ' NET_ID
                            if [[ $(pvesh get /nodes/${NODE_NAME}/network -type any_bridge --noborder --noheader | awk -F' ' '{print $10}' | wc -l) == 0 ]]; then
                                error "${NET_ID} is invalid. Try again..."
                                echo "------------------------------------"
                            else
                                break
                            fi
                        done
                    else
                        error "Could not detect ${HYPERVISOR} network interfaces."
                        read -p 'Please manually add the network interface via the Web Interface and press enter to continue' TEMP
                    fi
                    info "Adding network device"
                    if [[ ${NET_MAC:-} != "" && "${NET_MAC}" =~ ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$ ]]; then
                        MAC_ADDR=",macaddr=${NET_MAC}"
                    elif [[ ${NET_MAC:-} != "" ]]; then
                        MAC_ADDR=""
                        warning "Detected MAC address from previous VM invalid. MAC address won't be set for ${VM_NAME}"
                    else
                        MAC_ADDR=""
                    fi
                    qm set ${VM_ID} --net0 e1000,bridge=${NET_ID},firewall=1${MAC_ADDR:-}
                fi
            fi
        fi

        if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
            VM_RUNNING=$(vboxmanage showvminfo "${VM_NAME}" | grep -c "running (since" || true)
        elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
            VM_RUNNING=$(qm status ${VM_ID} | grep -c "running" || true)
        fi

        if [[ ${VM_RUNNING} = 0 ]]; then
            warn "VM is not running. Starting..."
            if [[ ${HYPERVISOR} == "VIRTUALBOX" ]]; then
                vboxmanage startvm ${VM_NAME} --type headless
            elif [[ ${HYPERVISOR} == "PROXMOX" ]]; then
                qm start ${VM_ID}
            fi
            sleep 5s

            notice "Waiting 60 seconds for ${VM_NAME} to boot"
            count=0
            VM_BOOT="${VM_HOST}"
            while true; do
                RESULT=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_BOOT} 2>/dev/null 'echo "OK"' || RETURN_CODE=$?)

                if [[ ${RESULT} == "OK" ]]; then
                    RESULT=""
                    echo ""
                    trace "Connection made!"
                    VM_IP=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_HOST} 'hostname -I' | awk '{print $1}' || true)
                    break
                elif [[ $count -ge 6 && ${VM_IP:-} != "" && ${RETURN_CODE:-} == 1 ]]; then
                    trace "Switching from VM_HOST (${VM_HOST}) to VM_IP (${VM_IP})"
                    VM_BOOT="${VM_IP}"
                elif [[ $count -ge 12 ]]; then
                    echo ""
                    break
                else
                    echo -n "."
                    sleep 5s
                fi
                count=$(($count+1))
            done
        else
            info "VM is running!"
        fi # VM running check

        if [[ ${VM_IP:-} == "" ]]; then
            notice "Getting IP address for ${VM_NAME}.."
            VALID_IP=0
            count=0
            denied=0
            while [[ ${VALID_IP} != 1 ]]; do
                echo -n "."
                # TODO: Put password into a file, for security
                VM_IP=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_HOST} 'hostname -I' | awk '{print $1}' || true)
                RETURN_CODE=$?

                if valid_ip $VM_IP; then
                    echo ""
                    info "${VM_NAME} IP Address: ${VM_IP}"
                    VALID_IP=1
                    break
                elif [ $RETURN_CODE = 5 ]; then
                    denied=$(($denied+1))
                fi

                if [ $count -ge 18 ]; then
                    fatal "Couldn't get the IP address of the VM"
                fi
                count=$(($count+1))
                sleep 10s
            done
        elif valid_ip $VM_IP; then
            info "${VM_NAME} IP Address: ${VM_IP}"
            VALID_IP=1
        else
            fatal "- No valid IP address provided"
        fi # Get IP address

        notice "Beginning configuration of ${VM_NAME}"
        readonly openflixr_start=$(date +%s)
        RESULT=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'echo "OK"'  2>/dev/null || true)
        debug "  RESULT=${RESULT}"
        if [[ ${RESULT} == "OK" && ${VALID_IP} == 1 ]]; then
            RESULT=""
            debug "- Checking if run_me.sh is running or has run"
            RUNME_LOG_EXISTS=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'ls -l /home/openflixr/.FirstRun/logs/run_me.log 2>/dev/null | wc -l' 2>/dev/null)
            if [[ ${RUNME_LOG_EXISTS} -eq 0 ]]; then
                debug "   Nope."
                RUNME_LOG_EXISTS=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'ls -l /home/openflixr/.FirstRun/logs/run_me.log 2>/dev/null | wc -l' 2>/dev/null)
                if [[ -f "${DATA_DIR}/test.config" ]]; then
                    info "Test config file found! Running test config file..."
                    sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'bash -s' < "${DATA_DIR}/test.config" 2>/dev/null || true
                    debug "  RETURN_CODE='$?'"
                fi
                debug "Adding information specific for this script"
                sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'mkdir -p ".FirstRun"' 2>/dev/null
                sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'touch ".FirstRun/.run_openflixr_vm"' 2>/dev/null
            else
                debug "   Yep."
            fi

            RUNME_RUNNING=0
            if [[ -f "${RUNME_PID_FILE}" ]]; then
                debug "'${RUNME_PID_FILE}' found"
                RUNME_PID=$(cat "${RUNME_PID_FILE}")
                debug "RUNME_PID='${RUNME_PID}'"
                if [ -e /proc/${RUNME_PID} -a /proc/${RUNME_PID}/exe ]; then
                    debug "'run_me.sh' is running"
                    RUNME_RUNNING=1
                else
                    debug "'run_me.sh' is NOT running"
                fi
            fi
            if [[ ${RUNME_RUNNING} == 0 ]]; then
                debug "'run_me.sh' is NOT running (2)"

                SCREEN_EXISTS=$(sshpass -p "openflixr" ssh -t -oStrictHostKeyChecking=accept-new openflixr@openflixr 'command -v screen || true' 2>/dev/null || true)
                SCREEN_RUNNING=$(sshpass -p "openflixr" ssh -t -oStrictHostKeyChecking=accept-new openflixr@openflixr 'screen -ls 2>/dev/null | grep -c "openflixr_setup" || true' 2>/dev/null || true)
                debug "SCREEN_EXISTS='${SCREEN_EXISTS}'"
                debug "SCREEN_RUNNING='${SCREEN_RUNNING}'"
                if [[ ${SCREEN_EXISTS} != "" && ${SCREEN_RUNNING} == "1" ]]; then
                    debug "Screen is running on ${VM_NAME}"
                else
                    debug "- Checking if OpenFLIXR2.FirstRun branch 'development' exists..."
                    DEV_URL_EXISTS=$(sshpass -p "${VM_PASSWORD}" ssh -t -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'curl -s --head https://raw.githubusercontent.com/openflixr/OpenFLIXR2.FirstRun/development/run_me.sh | head -1 | grep -c "HTTP/1.[01] [23].." || true' 2>/dev/null)
                    debug "DEV_URL_EXISTS='${DEV_URL_EXISTS}'"
                    if [[ ${DEV_URL_EXISTS:-} == "1" ]]; then
                        info "Running 'run_me.sh' from development..."
                        sshpass -p "${VM_PASSWORD}" ssh -t -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/openflixr/OpenFLIXR2.FirstRun/development/run_me.sh)" && bash OpenFLIXR2.FirstRun/startup.sh' >>"${LOG_FILE}" 2>&1 &
                        RUNME_PID=$!
                    else
                        info "Running 'run_me.sh' from master..."
                        sshpass -p "${VM_PASSWORD}" ssh -t -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/openflixr/OpenFLIXR2.FirstRun/master/run_me.sh)" && bash OpenFLIXR2.FirstRun/startup.sh' >>"${LOG_FILE}" 2>&1 &
                        RUNME_PID=$!
                    fi
                    echo "${RUNME_PID}" > "${RUNME_PID_FILE}"
                    info "'run_me.sh' is running with PID ${RUNME_PID}"
                fi
            else
                info "'run_me.sh' is already running with PID ${RUNME_PID}!"
            fi
            notice "Waiting on status changes..."
            count=0
            UPGRADE_STAGE="UPTIME"
            while true; do
                RESULT=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'echo "OK"' 2>/dev/null || true)
                RETURN_CODE=$?
                if [[ ${RESULT} != "OK" ]]; then
                    echo ""
                    notice "Connection to ${VM_NAME} lost. Probably because the system rebooted."
                    notice "Waiting for connection to ${VM_NAME}..."
                    conn_wait=5
                    conn_start=$(date +%s)
                    while true; do
                        RESULT=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'echo "OK"' 2>/dev/null || true)
                        RETURN_CODE=$?
                        if [[ ${RESULT} == "OK" ]]; then
                            echo ""
                            RESULT=""
                            info "Connection made!"
                            break
                        else
                            echo -n "."
                            sleep 5s
                        fi

                        conn_elapsed=$(($(date +%s)-$conn_start))
                        conn_minutes=$(date -ud @$conn_elapsed +%M)
                        if [[ ${conn_minutes#0} -ge ${conn_wait} || $count -ge 100 ]]; then
                            error "Couldn't reconnect to the VM after ~120 seconds"
                            fatal "Aborting script. Run this again once the VM has booted."
                        fi
                        count=$(($count+1))
                    done
                    sleep 5s
                    #echo "Starting screen session on ${VM_NAME}"
                    #sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'screen -dmS openflixr_setup' 2>/dev/null
                    #sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'screen -x -R openflixr_setup' 2>/dev/null
                    notice "Waiting on status changes..."
                fi
                SETUP_CONFIG_EXISTS=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'ls -l /home/openflixr/openflixr_setup/openflixr_setup.config 2>/dev/null | wc -l' 2>/dev/null || true)
                if [[ ${SETUP_CONFIG_EXISTS} -ge 1 ]]; then
                    if [[ ${UPGRADE_STAGE} == "UPTIME" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_UPTIME=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "Uptime Check completed!"
                        info "Waiting on Process Check"
                        UPGRADE_STAGE="PROCESS_CHECK"
                    fi
                    if [[ ${UPGRADE_STAGE} == "PROCESS_CHECK" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_PROCESSCHECK=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1  ]]; then
                        count=0
                        echo ""
                        notice "Process Check completed!"
                        sleep 5s
                        if [[ $(tail -5 "${LOG_FILE}" | grep -c "Must be connected to a terminal.") == 1 ]]; then
                            notice "The remaining stages are running in a Screen session on the VM"
                            notice "You may connect to the VM to see what it is doing and disconnect at any time."
                        fi
                        info "Waiting on DNS Check"
                        UPGRADE_STAGE="DNS_CHECK"
                    fi
                    if [[ ${UPGRADE_STAGE} == "DNS_CHECK" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_DNSCHECK=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "DNS Check Completed!"
                        info "Waiting on Pre-upgrade"
                        UPGRADE_STAGE="PREPARE"
                    fi
                    if [[ ${UPGRADE_STAGE} == "PREPARE" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_PREPARE_UPGRADE=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "Pre-upgrade completed!"
                        info "Waiting on Upgrade"
                        UPGRADE_STAGE="UPGRADE"
                    fi
                    if [[ ${UPGRADE_STAGE} == "UPGRADE" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_UPGRADE=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "Upgrade completed!"
                        info "Waiting on Fixes"
                        UPGRADE_STAGE="FIXES"
                    fi
                    if [[ ${UPGRADE_STAGE} == "FIXES" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_FIXES=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "Fixes completed!"
                        info "Waiting on Cleanup"
                        UPGRADE_STAGE="CLEANUP"
                    fi
                    if [[ ${UPGRADE_STAGE} == "CLEANUP" && $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "FIRSTRUN_CLEANUP=COMPLETED" "/home/openflixr/openflixr_setup/openflixr_setup.config"' 2>/dev/null || true) == 1 ]]; then
                        count=0
                        echo ""
                        notice "System Ready!"
                        UPGRADE_STAGE="COMPLETE"
                        break
                    fi
                    if [[ $(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} 'grep -c "Well, this is unexpected" "/var/log/openflixr_setup.log"' 2>/dev/null || true) == 1 ]]; then
                        error "Something has gone horribly wrong during the ${UPGRADE_STAGE} stage =("
                        break
                    fi
                else
                    debug "Setup log doesn't exist on ${VM_NAME}"
                fi
                sleep 5s
                if [[ ${count} -ge 48 ]]; then
                    count=0
                    echo ""
                else
                    echo -n "."
                    count=$((count+1))
                fi
            done

            if [[ ${UPGRADE_STAGE} == "COMPLETE" && -v TEST_MODE && ${TEST_MODE} == 1 ]]; then
                notice "Giving the server some time to settle..."
                sleep 120s
                echo ""
                notice "Checking services"
                declare -A SERVICES
                SERVICES=(
                    [AutoSub]=autosub
                    [CouchPotato]=couchpotato
                    [Headphones]=headphones
                    [HomeAssistant]=home-assistant
                    [HTPCmanager]=htpcmanager
                    [Hydra2]=nzbhydra2
                    [Jackett]=jackett
                    [Lidarr]=lidarr
                    [LazyLibrarian]=lazylibrarian
                    [Mopidy]=mopidy
                    [Monit]=monit
                    [Mylar]=mylar
                    [nginx]=nginx
                    [NZBget]=nzbget
                    [Ombi]=ombi
                    [Pi-Hole]=pihole-FTL
                    [Plex]=plexmediaserver
                    [PlexPy]=plexpy
                    [QBittorrent]=qbittorrent
                    [Radarr]=radarr
                    [SABnzbd]=sabnzbdplus
                    [SickRage]=sickrage
                    [Sonarr]=sonarr
                    [Ubooquity]=ubooquity
                    [Webmin]=webmin
                )
                NOT_RUNNING_COUNT=0
                NOT_RUNNING=()
                for service in "${!SERVICES[@]}"; do
                    #echo "- ${service}"
                    RESULT=$(sshpass -p "${VM_PASSWORD}" ssh -oStrictHostKeyChecking=accept-new ${VM_USERNAME}@${VM_IP} "service ${SERVICES[$service]} status | grep 'Active:'" || true)
                    if [[ $(grep -c "active (" <<< ${RESULT}) == 0 ]]; then
                        NOT_RUNNING+=(${service})
                        NOT_RUNNING_COUNT=$((NOT_RUNNING_COUNT+1))
                    fi
                done
                echo ""
                test_elapsed=$(($(date +%s)-$test_start))
                test_duration=$(date -ud @${test_elapsed} +'%H hours %M minutes %S seconds')
                notice "----------------------------------------------------------------------------"
                if [[ ${NOT_RUNNING_COUNT} -gt 0 ]]; then
                    warn "${NOT_RUNNING_COUNT} services are not running:"
                    for service in "${NOT_RUNNING[@]}"; do
                        warn "- ${service}"
                    done
                else
                    notice "All checked services are running!"
                fi
                notice "Test took ${test_duration}"
            fi

            openflixr_elapsed=$(($(date +%s)-$openflixr_start))
            openflixr_duration=$(date -ud @${openflixr_elapsed} +'%H hours %M minutes %S seconds')
            if [[ ${UPGRADE_STAGE} == "COMPLETE" ]]; then
                notice "${VM_NAME} is ready! It took ${openflixr_duration}"
            else
                notice "${VM_NAME} took ${openflixr_duration} to fail..."
            fi
        elif [[ ${RESULT} == "" ]]; then
            fatal "Unable to connect to ${VM_NAME} using ${VM_IP}"
        fi # Result & Valid IP

    fi # CI check
}
main
