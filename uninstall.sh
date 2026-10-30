#!/bin/sh
# Remove the Claude access guard (ipguard) on macOS: the launchd autostart is removed and the
# service is stopped. Settings, journal and binary stay — the settings hold the secret, the
# journal holds the history of refusals. The proxy is dropped from the claude settings
# separately: `ipguard disable`.
set -eu

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
	echo "ipguard: Go is required — https://go.dev/dl/" >&2
	exit 1
fi

build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

GOWORK=off go build -trimpath -o "$build/ipguard" ./cmd/ipguard

"$build/ipguard" uninstall "$@"
