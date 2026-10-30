#!/bin/sh
# Install the Claude access guard (ipguard) on macOS: build from this folder and run `ipguard
# install` — install directory, binary, settings with a secret, launchd autostart and a live
# service probe. All the logic is in Go (`cmd/ipguard`); this script only builds: the folder
# can be zipped and handed to a colleague as is.
#
#   ./install.sh                      # asks for the external IP and a confirmation
#   ./install.sh --yes                # accept the current external IP without asking
#   ./install.sh --expected-ip <ip>
#
# A second run redoes nothing: every step prints `=` when it is already done.
set -eu

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
	echo "ipguard: Go is required — https://go.dev/dl/" >&2
	exit 1
fi

build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

# GOWORK=off: the folder is its own module, and a zipped copy next to a foreign go.work does
# not need it. -trimpath: otherwise the build path lives in the binary, and the same code built
# from another folder gives other bytes — the "binary" step would stop being idempotent.
GOWORK=off go build -trimpath -o "$build/ipguard" ./cmd/ipguard

"$build/ipguard" install "$@"
