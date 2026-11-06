#!/usr/bin/env bash
#
# Description: Automates the generation of a Linux Reverse Shell SIGMA detection rule.
#

set -euo pipefail

# Default Configuration
TITLE="Linux Interactive Reverse Shell Execution"
AUTHOR="Detection Engineering Team"
LEVEL="high"
STATUS="experimental"
OUTPUT\_FILE="lnx\_reverse\_shell\_detection.yml"


# Function: Display usage
usage() {
    cat <<EOF
Usage: $(basename "$0") \[OPTIONS]

Options:
  -t, --title <title>       Rule title (Default: "$TITLE")
  -a, --author <author>     Rule author (Default: "$AUTHOR")
  -l, --level <level>       Severity level: low, medium, high, critical (Default: "$LEVEL")
  -s, --status <status>     Rule status: experimental, test, stable (Default: "$STATUS")
  -o, --output <filename>   Output YAML file (Default: "$OUTPUT\_FILE")
  -h, --help                Show this help message

Example:
  $(basename "$0") -t "Suspicious Reverse Shell Command" -l critical -o custom\_rule.yml
EOF
    exit 0
}

# Function: Generate RFC 4122 UUID v4
generate\_uuid() {
    if command -v uuidgen >/dev/null 2>\&1; then
        uuidgen | tr '\[:upper:]' '\[:lower:]'
    elif \[\[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        od -x /dev/urandom | head -1 | awk '{OFS="-"; print $2$3,$4,$5,$6,$7$8$9}'
    fi
}

# Parse command line flags
while \[\[ $# -gt 0 ]]; do
    case "$1" in
        -t|--title) TITLE="$2"; shift 2 ;;
        -a|--author) AUTHOR="$2"; shift 2 ;;
        -l|--level) LEVEL="$2"; shift 2 ;;
        -s|--status) STATUS="$2"; shift 2 ;;
        -o|--output) OUTPUT\_FILE="$2"; shift 2 ;;
        -h|--help) usage ;;
        \*) echo "\[-] Error: Unknown argument $1" >\&2; usage ;;
    esac
done

RULE\_ID=$(generate\_uuid)
DATE\_TODAY=$(date -u +"%Y-%m-%d")

echo "\[\*] Generating SIGMA rule: '$TITLE'..."
echo "\[\*] Rule ID: $RULE\_ID"
echo "\[\*] Destination: $OUTPUT\_FILE"

cat <<EOF > "$OUTPUT\_FILE"
title: ${TITLE}
id: ${RULE\_ID}
status: ${STATUS}
description: Detects command-line execution patterns characteristic of interactive Linux reverse shell attempts via Bash network redirects, Netcat, scripting runtimes, or named pipes.
references:
    - ${REFERENCE\_URL}
    - https://attack.mitre.org/techniques/T1059/004/
author: ${AUTHOR}
date: ${DATE\_TODAY}
modified: ${DATE\_TODAY}
tags:
    - attack.execution
    - attack.t1059.004
    - attack.persistence
logsource:
    category: process\_creation
    product: linux
detection:
    selection\_bash\_dev\_tcp:
        CommandLine|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
            - '>\& /dev/tcp/'
            - '>\& /dev/udp/'
            - 'exec 5<>/dev/tcp/'

    selection\_sh\_redirect:
        CommandLine|contains:
            - 'sh -i >\&'
            - 'bash -i >\&'
            - '0<\&1'
            - '0>\&1'

    selection\_netcat:
        CommandLine|contains:
            - 'nc -e /'
            - 'nc.traditional -e /'
            - 'ncat -e /'
            - 'ncat --exec /'
            - 'nc -c /'

    selection\_inline\_interpreters:
        CommandLine|contains:
            - 'socket.socket('
            - 'pty.spawn('
            - 'TCPSocket.new('
            - 'TCPSocket.open('
            - 'fsockopen('
            - 'use Socket;'

    selection\_socat:
        CommandLine|contains:
            - 'socat exec:'
            - 'socat tcp-connect:'
            - 'socat tcp4-connect:'

    selection\_fifo:
        CommandLine|contains:
            - 'mkfifo /tmp/'
            - 'mknod /tmp/'

    condition: 1 of selection\_\*
falsepositives:
    - Legitimate administrator automation or remote maintenance utilities
    - Specialized local container synchronization scripts
level: ${LEVEL}
EOF

echo "\[+] Successfully generated: $OUTPUT\_FILE"
