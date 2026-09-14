#!/usr/bin/env bash
set -euo pipefail

export IMAGE="${IMAGE:-ghcr.io/jetrabbits/openflux}"
export TAG="${TAG:-latest}"
export PLATFORMS="${PLATFORMS:-linux/amd64}"
export PUSH=true

exec "$(dirname "$0")/build_docker.sh"
