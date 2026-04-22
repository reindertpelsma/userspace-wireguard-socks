#!/usr/bin/env sh
set -eu

VERSION="${VERSION:-latest}"
if [ -z "${PREFIX:-}" ]; then
  if command -v id >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    PREFIX=/usr/local/bin
  else
    PREFIX="${HOME}/.local/bin"
  fi
fi

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 127
  }
}

need uname
need curl
need mktemp
warn_path() {
  case ":${PATH:-}:" in
    *:"$PREFIX":*) ;;
    *)
      printf 'installed binaries in %s; add that directory to PATH if needed\n' "$PREFIX" >&2
      ;;
  esac
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
os="${TARGET_OS:-$os}"
arch="${TARGET_ARCH:-$arch}"

case "$os" in
  linux|darwin|freebsd|openbsd) ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  riscv64) arch=riscv64 ;;
  mips64) arch=mips64 ;;
  mips64el|mips64le) arch=mips64le ;;
  mips) arch=mips ;;
  mipsel|mipsle) arch=mipsle ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

detect_libc() {
  if [ -n "${TARGET_LIBC:-}" ]; then
    printf '%s\n' "$TARGET_LIBC"
    return
  fi
  if command -v ldd >/dev/null 2>&1; then
    if ldd --version 2>&1 | grep -qi musl; then
      printf '%s\n' musl
      return
    fi
    if ldd --version 2>&1 | grep -qi 'glibc\|gnu libc'; then
      printf '%s\n' gnu
      return
    fi
  fi
  if command -v getconf >/dev/null 2>&1 && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
    printf '%s\n' gnu
    return
  fi
  printf '%s\n' gnu
}

repo_for_product() {
  case "$1" in
    uwgsocks|uwgsocks-lite|turn|uwgwrapper) printf '%s\n' reindertpelsma/userspace-wireguard-socks ;;
    uwgsocks-ui|uwgkm) printf '%s\n' reindertpelsma/simple-wireguard-server ;;
    *)
      echo "unsupported product: $1" >&2
      exit 1
      ;;
  esac
}

binary_name() {
  case "$1" in
    uwgsocks|uwgsocks-lite) printf '%s\n' uwgsocks ;;
    turn) printf '%s\n' turn ;;
    uwgwrapper) printf '%s\n' uwgwrapper ;;
    uwgsocks-ui) printf '%s\n' uwgsocks-ui ;;
    uwgkm) printf '%s\n' uwgkm ;;
  esac
}

asset_name() {
  product="$1"
  case "$product" in
    uwgsocks) printf 'uwgsocks-%s-%s\n' "$os" "$arch" ;;
    uwgsocks-lite) printf 'uwgsocks-lite-%s-%s\n' "$os" "$arch" ;;
    turn) printf 'turn-%s-%s\n' "$os" "$arch" ;;
    uwgsocks-ui) printf 'uwgsocks-ui-%s-%s\n' "$os" "$arch" ;;
    uwgkm)
      [ "$os" = "linux" ] || {
        echo "uwgkm is only published for linux" >&2
        exit 1
      }
      printf 'uwgkm-linux-%s\n' "$arch"
      ;;
    uwgwrapper)
      [ "$os" = "linux" ] || {
        echo "uwgwrapper is only published for linux" >&2
        exit 1
      }
      printf 'uwgwrapper-linux-%s-%s\n' "$arch" "$(detect_libc)"
      ;;
  esac
}

download_url() {
  repo="$1"
  asset="$2"
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$repo" "$asset"
  else
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$repo" "$VERSION" "$asset"
  fi
}

download_asset() {
  product="$1"
  repo="$(repo_for_product "$product")"
  asset="$(asset_name "$product")"
  tmp_bin="$(mktemp)"
  trap 'rm -f "$tmp_bin"' EXIT INT TERM

  mkdir -p "$PREFIX"
  dst="$PREFIX/$(binary_name "$product")"
  curl -fsSL -A 'uwgsocks-installer' "$(download_url "$repo" "$asset")" -o "$tmp_bin"
  cp "$tmp_bin" "$dst"
  chmod +x "$dst"
  rm -f "$tmp_bin"
  printf 'installed %s to %s\n' "$asset" "$dst"
  trap - EXIT INT TERM
}

if [ "$#" -eq 0 ]; then
  set -- "${PRODUCT:-uwgsocks}"
fi

for product in "$@"; do
  download_asset "$product"
done

warn_path
