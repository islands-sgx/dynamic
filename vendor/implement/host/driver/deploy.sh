#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RESULT=${SGX_KERNEL_RESULT:-"$ROOT/result"}
ACTION=${1:-}

usage() {
  printf 'usage: %s prepare|plan|apply\n' "$0" >&2
  exit 2
}

need_result() {
  [[ -d "$RESULT/packages" && -f "$RESULT/metadata/kernel.release" ]] || {
    printf 'No prepared kernel package set. Run: %s prepare\n' "$0" >&2
    exit 1
  }
}

stock_guard() {
  local running stock_image stock_pkg
  running=$(uname -r)
  stock_image="/boot/vmlinuz-$running"
  [[ -e "$stock_image" ]] || { printf 'Running kernel image is missing: %s\n' "$stock_image" >&2; exit 1; }
  stock_pkg=$(dpkg-query -S "$stock_image" 2>/dev/null | cut -d: -f1 | head -n 1)
  [[ -n "$stock_pkg" ]] || { printf 'Cannot identify the installed stock kernel package for %s\n' "$stock_image" >&2; exit 1; }
  printf '%s\n' "$stock_pkg"
}

case "$ACTION" in
  prepare)
    build_flake=$(mktemp -d "${TMPDIR:-/tmp}/sgx-kernel-flake.XXXXXX")
    trap 'rm -rf "$build_flake"' EXIT
    mkdir -p "$build_flake/config" "$build_flake/patches"
    cp "$ROOT/flake.nix" "$ROOT/flake.lock" "$build_flake/"
    cp "$ROOT/config/ubuntu-26.04.1-7.0.0-38-generic.config" "$build_flake/config/"
    cp "$ROOT/patches/linux-sgx-page-readiness.patch" "$build_flake/patches/"
    nix build "$build_flake#kernel-debs" -o "$RESULT"
    rm -rf "$build_flake"
    trap - EXIT
    printf 'Prepared package set: %s\n' "$RESULT"
    ;;
  plan)
    need_result
    stock_pkg=$(stock_guard)
    candidate=$(<"$RESULT/metadata/kernel.release")
    running=$(uname -r)
    [[ "$candidate" != "$running" ]] || { printf 'Candidate release equals the running stock release.\n' >&2; exit 1; }
    printf 'Running stock kernel: %s (%s)\n' "$running" "$stock_pkg"
    printf 'Candidate kernel release: %s\n' "$candidate"
    printf 'Build output package inventory:\n'
    cat "$RESULT/metadata/packages.tsv"
    image_deb=
    for deb in "$RESULT"/packages/*.deb; do
      if [[ "$(dpkg-deb -f "$deb" Package)" == "linux-image-$candidate" ]]; then
        image_deb=$deb
      fi
    done
    [[ -n "$image_deb" ]] || { printf 'Missing exact image package linux-image-%s.\n' "$candidate" >&2; exit 1; }
    printf 'Planned install package: %s\n' "$(dpkg-deb -f "$image_deb" Package)"
    printf 'Planned installation command (no reboot):\n  sudo apt-get --no-remove --no-upgrade install'
    printf ' \\\n    %q' "$image_deb"
    printf '\n'
    printf 'Headers remain in the build output; their helper ELFs currently reference Nix-store runtimes and are excluded from deployment.\n'
    printf 'The stock package %s and /boot/vmlinuz-%s remain installed.\n' "$stock_pkg" "$running"
    ;;
  apply)
    need_result
    [[ $EUID -eq 0 ]] || { printf 'Run apply as root after reviewing plan output.\n' >&2; exit 1; }
    stock_pkg=$(stock_guard)
    candidate=$(<"$RESULT/metadata/kernel.release")
    running=$(uname -r)
    [[ "$candidate" != "$running" ]] || { printf 'Refusing to replace the running kernel release.\n' >&2; exit 1; }
    if command -v mokutil >/dev/null && mokutil --sb-state 2>/dev/null | grep -qi 'SecureBoot enabled'; then
      printf 'Secure Boot is enabled; sign the candidate kernel and modules before apply.\n' >&2
      exit 1
    fi
    image_deb=
    for deb in "$RESULT"/packages/*.deb; do
      if [[ "$(dpkg-deb -f "$deb" Package)" == "linux-image-$candidate" ]]; then
        [[ -z "$image_deb" ]] || { printf 'Multiple exact image packages found.\n' >&2; exit 1; }
        image_deb=$deb
      fi
    done
    [[ -n "$image_deb" ]] || { printf 'Missing exact image package linux-image-%s.\n' "$candidate" >&2; exit 1; }
    apt-get --no-remove --no-upgrade install "$image_deb"
    [[ -e "/boot/vmlinuz-$running" ]] || { printf 'Stock image disappeared; stopping.\n' >&2; exit 1; }
    [[ -e "/boot/initrd.img-$candidate" ]] || update-initramfs -c -k "$candidate"
    update-grub
    printf 'Installed %s. Stock %s remains installed. No reboot was requested.\n' "$candidate" "$stock_pkg"
    ;;
  *) usage ;;
esac
