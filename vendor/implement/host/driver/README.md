# Ubuntu SGX page-readiness host kernel

This directory carries a Linux SGX driver patch, pinned Nix source/build, the exact Ubuntu generic kernel configuration snapshot, and an explicit deployment gate. It builds the Ubuntu `linux=7.0.0-38.38` source tree as upstream kernel and module release `7.0.14-islands-sgx`, with Debian package version `7.0.0-islands-sgx-1`; Ubuntu's `7.0.0-38-generic` stock kernel remains installed.

`flake.nix` fetches Ubuntu `linux=7.0.0-38.38` source package members by fixed SHA-256, unpacks the verified Debian source descriptor, applies `patches/linux-sgx-page-readiness.patch`, and builds binary image and headers packages from the recorded generic config. `flake.lock` pins the Nix toolchain input.

Run from this directory:

```sh
./deploy.sh prepare
./deploy.sh plan
```

The prepare action creates image, headers, debug-image, and libc-dev packages under the ignored result symlink. The image package contains the built-in SGX driver and modules for 7.0.14-islands-sgx. The headers package is retained as a build artifact, but its helper ELF files currently carry interpreter and runtime search paths into the Nix store; it is not portable to the Ubuntu host and plan/apply exclude it. The plan action prints the package inventory and exact APT command for the matching image package only. After reviewing the plan, apply requires root, refuses an enabled Secure Boot state, installs only that image package with APT's --no-remove --no-upgrade, checks the stock image remains present, ensures an initramfs and GRUB menu entry, and does not reboot.

The driver source patch exposes `SGX_MAGIC=0xA4`, ACQUIRE ioctl `0x0A`, RELEASE ioctl `0x0B`, and the shared three-u64 request structure. The compiled scope is Linux's built-in x86 SGX driver; this is not an out-of-tree module.
