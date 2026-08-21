#!/usr/bin/env sh

set -eu

GITHUB_REPO="changhoon-sung/wush"
BINARY_NAME="wush"
INSTALL_DIR="/usr/local/bin"

# Function to determine the platform
detect_platform() {
  OS=$(uname -s)
  ARCH=$(uname -m)

  case $OS in
    Linux)
      PLATFORM="linux"
      ;;
    Darwin)
      PLATFORM="darwin"
      ;;
    *)
      echo "Unsupported OS: $OS"
      exit 1
      ;;
  esac

  case $ARCH in
    x86_64|amd64)
      ARCH="amd64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  echo "${PLATFORM}_${ARCH}"
}

main() {
  PLATFORM_ARCH=$(detect_platform)
  ASSET_NAME="${BINARY_NAME}_${PLATFORM_ARCH}"

  # Get the latest release download URL from GitHub API
  LATEST_RELEASE_URL=$(curl -fsSL \
    "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
        | grep "browser_download_url" \
        | grep "/$ASSET_NAME\"" \
        | cut -d '"' -f 4 | head -n 1)

  if [ -z "$LATEST_RELEASE_URL" ]; then
    echo "No release found for $PLATFORM_ARCH"
    exit 1
  fi

  # Download the release binary.
  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT
  BINARY_PATH="$TMP_DIR/$ASSET_NAME"

  echo "Downloading $BINARY_NAME from $LATEST_RELEASE_URL..."
  curl -fL -o "$BINARY_PATH" "$LATEST_RELEASE_URL"

  # Make the binary executable
  chmod +x "$BINARY_PATH"

  # Install the binary. Run using sudo if not root.
  if [ "$(id -u)" -ne 0 ]; then
    sudo sh <<EOF
      if [ "$(uname -s)" = "Linux" ]; then
        if command -v setcap >/dev/null 2>&1; then
          setcap cap_net_admin=eip "$BINARY_PATH"
        else
          echo "Warning: 'setcap' command is not available. Transfer speeds may be slower."
        fi
      fi
      mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
EOF
  else
    if [ "$(uname -s)" = "Linux" ]; then
      if command -v setcap >/dev/null 2>&1; then
        setcap cap_net_admin=eip "$BINARY_PATH"
      else
        echo "Warning: 'setcap' command is not available. Transfer speeds may be slower."
      fi
    fi
    mv "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"
  fi

  echo "$BINARY_NAME installed successfully!"
}

# Run the installation
main
