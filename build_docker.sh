#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-ghcr.io/jetrabbits/openflux}"
TAG="${TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64}"
PUSH="${PUSH:-false}"

if [[ "${PUSH}" == "true" ]]; then
  ACTION=(--push)
else
  # --load works only for a single platform and is convenient for local smoke tests.
  ACTION=(--load)
fi

echo "Building ${IMAGE}:${TAG} for ${PLATFORMS} (push=${PUSH})"

docker buildx build \
  --platform "${PLATFORMS}" \
  -t "${IMAGE}:${TAG}" \
  "${ACTION[@]}" \
  .
