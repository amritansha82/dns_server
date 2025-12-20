#!/bin/bash
#
# DNS Server run script
# Usage: ./run.sh [--resolver <ip:port>]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Build the project if needed
if [ ! -f "build/dns-server" ] || [ "src/main.cpp" -nt "build/dns-server" ]; then
    echo "Building DNS server..."
    make
fi

# Run the server
exec ./build/dns-server "$@"
