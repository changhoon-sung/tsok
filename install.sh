#!/usr/bin/env sh

set -eu

GITHUB_REPO="changhoon-sung/tsok"
BINARY_NAME="tsok"
INSTALL_DIR="${HOME:?HOME must be set}/.local/bin"

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
  ARCHIVE_NAME="${BINARY_NAME}_${PLATFORM_ARCH}.tar.gz"

  # Get the matching archive from the latest GitHub release.
  LATEST_RELEASE_URL=$(curl -fsSL \
    "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
        | grep "browser_download_url" \
        | grep "/$ARCHIVE_NAME\"" \
        | cut -d '"' -f 4 | head -n 1)

  if [ -z "$LATEST_RELEASE_URL" ]; then
    echo "No tsok release archive found for $PLATFORM_ARCH" >&2
    exit 1
  fi

  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/tsok-install.XXXXXX")
  ARCHIVE_PATH="$TMP_DIR/$ARCHIVE_NAME"
  BINARY_PATH="$TMP_DIR/$BINARY_NAME"
  cleanup() {
    rm -f -- "$ARCHIVE_PATH" "$BINARY_PATH"
    rmdir -- "$TMP_DIR" 2>/dev/null || true
  }
  trap cleanup EXIT
  trap 'exit 1' HUP INT TERM

  echo "Downloading $ARCHIVE_NAME..."
  curl -fsSL -o "$ARCHIVE_PATH" "$LATEST_RELEASE_URL"

  if [ "$(tar -tzf "$ARCHIVE_PATH")" != "$BINARY_NAME" ]; then
    echo "Release archive contains unexpected files" >&2
    exit 1
  fi
  tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"
  if [ ! -f "$BINARY_PATH" ]; then
    echo "Release archive does not contain $BINARY_NAME" >&2
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$BINARY_PATH" "$INSTALL_DIR/$BINARY_NAME"

  echo "$BINARY_NAME installed to $INSTALL_DIR/$BINARY_NAME"
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      echo 'Add tsok to your PATH:'
      # Keep these variables literal so the user can paste the command.
      # shellcheck disable=SC2016
      echo '  export PATH="$HOME/.local/bin:$PATH"'
      ;;
  esac
}

# Run the installation
main
