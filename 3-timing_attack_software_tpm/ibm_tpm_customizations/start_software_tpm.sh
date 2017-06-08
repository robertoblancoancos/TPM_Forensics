#!/bin/sh

# Set env. variables for SW TPM server
export TPM_PATH=/home/roberto/ibm_tpm/nv_storage
export TPM_PORT=6545
export TPM_SERVER_PORT=6545
export TPM_SERVER_NAME=localhost
export TPM_SESSION=oiap

# Stop Tousers service (probably linked to the hardware TPM)
service tcsd stop

# Stop other tasks that might be running
pkill tcsd
pkill tpm_server

# Set fixed CPU frequency
cpufreq-set -c 0 --min 800MHz
cpufreq-set -c 0 --max 800MHz
cpufreq-set -c 1 --min 800MHz
cpufreq-set -c 1 --max 800MHz
cpufreq-set -c 2 --min 800MHz
cpufreq-set -c 2 --max 800MHz
cpufreq-set -c 3 --min 800MHz
cpufreq-set -c 3 --max 800MHz

# Isolate CPUs for the TPM server
cset shield -c 3

# Launch SW TPM server
cd ~/ibm_tpm/tpm4720/tpm
cset shield -e chrt -- --rr 99 ./tpm_server > /dev/null 2>&1 &

# Launch SW TPM Bios app
cd ~/ibm_tpm/tpm4720/libtpm/utils
sleep 2
./tpmbios

# Execute Trousers (which will now link to the SW TPM)
tcsd -e

# Display currently active TPM
tpm_version
