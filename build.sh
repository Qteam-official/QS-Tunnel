#!/bin/bash

set -e

mkdir -p build

TARGETS=(
  "linux amd64"
  "linux arm64"
  "linux 386"
  "linux arm"
)

build_binary() {
    NAME=$1
    CMD_PATH=$2

    for TARGET in "${TARGETS[@]}"; do
        read -r GOOS GOARCH <<< "$TARGET"

        OUTPUT="build/${NAME}-${GOOS}-${GOARCH}"

        echo "[*] Building $OUTPUT"

        if [ "$GOARCH" = "arm" ]; then
            GOARM=7 CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
            go build -trimpath -ldflags="-s -w" \
            -o "$OUTPUT" "./cmd/$CMD_PATH"
        else
            CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH \
            go build -trimpath -ldflags="-s -w" \
            -o "$OUTPUT" "./cmd/$CMD_PATH"
        fi
    done
}

build_binary "client" "client"
build_binary "server" "server"

echo "[✓] All builds completed."