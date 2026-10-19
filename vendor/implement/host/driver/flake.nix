{
  description = "Pinned Ubuntu 7.0.0-38.38 SGX page-readiness kernel build";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/f20cd90e28fe0403873f473b29e42662cd86e8c4";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      srcOrig = pkgs.fetchurl {
        url = "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_7.0.0.orig.tar.gz";
        hash = "sha256-xjQ3lcjH5P7/VfWzCTZcjg6vSc1qvLQS4yMVMT8UlTY=";
      };
      srcDiff = pkgs.fetchurl {
        url = "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_7.0.0-38.38.diff.gz";
        hash = "sha256-mOkT1KHB+BDk3PpXPLzw8aOkQnvc1QNyJVUpinlMUrI=";
      };
      srcDsc = pkgs.fetchurl {
        url = "https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux_7.0.0-38.38.dsc";
        hash = "sha256-AW1DV3vYphYpoC4UDjuIBytczdHJDLHOLzyOXCh1bn4=";
      };
      kernelSource = pkgs.stdenvNoCC.mkDerivation {
        pname = "linux-sgx-page-readiness-source";
        version = "7.0.0-38.38";
        nativeBuildInputs = [ pkgs.dpkg pkgs.patch ];
        dontFixup = true;
        dontUnpack = true;
        buildPhase = ''
          runHook preBuild
          mkdir source-package
          ln -s ${srcOrig} source-package/linux_7.0.0.orig.tar.gz
          ln -s ${srcDiff} source-package/linux_7.0.0-38.38.diff.gz
          ln -s ${srcDsc} source-package/linux_7.0.0-38.38.dsc
          dpkg-source -x source-package/linux_7.0.0-38.38.dsc source
          cd source
          patch --fuzz=0 -p1 -i ${./patches/linux-sgx-page-readiness.patch}
          runHook postBuild
        '';
        installPhase = ''
          mkdir -p "$out"
          cp -a . "$out/"
        '';
      };
      debhelperArchive = pkgs.fetchurl {
        url = "https://archive.ubuntu.com/ubuntu/pool/main/d/debhelper/debhelper_13.31ubuntu1_all.deb";
        hash = "sha256-jogyMuu6dxmbqRZDSnxHDFKLh1e/NEfb/uzy+5XB7ZU=";
      };
      libDebhelperArchive = pkgs.fetchurl {
        url = "https://archive.ubuntu.com/ubuntu/pool/main/d/debhelper/libdebhelper-perl_13.31ubuntu1_all.deb";
        hash = "sha256-QrrpOK5hOSrqtdMiUWZcCsqu1o3etDlxCEacvescWKY=";
      };
      debhelperTools = pkgs.runCommand "ubuntu-debhelper-13.31ubuntu1" {
        nativeBuildInputs = with pkgs; [ coreutils dpkg perl python3 bash ];
      } ''
        mkdir -p "$out/bin"
        dpkg-deb -x ${debhelperArchive} "$out"
        dpkg-deb -x ${libDebhelperArchive} "$out"
        patchShebangs "$out/usr/bin"
        for program in "$out"/usr/bin/*; do
          ln -s "../usr/bin/$(basename "$program")" "$out/bin/$(basename "$program")"
        done
      '';
      kernelPackages = pkgs.stdenv.mkDerivation {
        pname = "linux-sgx-page-readiness-kernel";
        version = "7.0.0-38.38-islands-sgx";
        src = kernelSource;
        nativeBuildInputs = (with pkgs; [
          bc bison coreutils cpio dpkg findutils flex gawk gzip inetutils kmod lz4 openssl pahole perl
          pkg-config python3 rsync util-linux xz zstd fakeroot
        ]) ++ [ debhelperTools ];
        buildInputs = with pkgs; [ elfutils libelf ncurses openssl zlib ];
        enableParallelBuilding = false;
        PERL5LIB = "${debhelperTools}/usr/share/perl5:${pkgs.dpkg}/lib/perl5/site_perl";
        dontConfigure = true;
        buildPhase = ''
          runHook preBuild
          cp ${./config/ubuntu-26.04.1-7.0.0-38-generic.config} .config
          bash scripts/config --file .config --set-str LOCALVERSION "-islands-sgx"
          bash scripts/config --file .config --disable LOCALVERSION_AUTO
          make olddefconfig
          test -s debian/canonical-certs.pem
          test -s debian/canonical-revoked-certs.pem
          cp debian/canonical-certs.pem certs/ubuntu-canonical-certs.pem
          cp debian/canonical-revoked-certs.pem certs/ubuntu-canonical-revoked-certs.pem
          bash scripts/config --file .config --set-str SYSTEM_TRUSTED_KEYS "certs/ubuntu-canonical-certs.pem"
          bash scripts/config --file .config --set-str SYSTEM_REVOCATION_KEYS "certs/ubuntu-canonical-revoked-certs.pem"
          make olddefconfig
          export SOURCE_DATE_EPOCH=1788507075
          export KBUILD_BUILD_TIMESTAMP="Fri Sep 04 07:31:15 UTC 2026"
          export KBUILD_BUILD_USER=nix-builder
          export KBUILD_BUILD_HOST=islands-sgx
          export KBUILD_BUILD_VERSION=1
          grep -qx 'CONFIG_X86_SGX=y' .config
          grep -qx 'CONFIG_MODULES=y' .config
          python3 - <<'PATCH_BPF_DOC'
          from pathlib import Path
          path = Path("tools/lib/bpf/Makefile")
          source = path.read_text()
          needle = "$(QUIET_GEN)$(srctree)/scripts/bpf_doc.py"
          replacement = "$(QUIET_GEN)python3 $(srctree)/scripts/bpf_doc.py"
          if source.count(needle) != 1:
              raise SystemExit("expected one bpf_doc.py build invocation")
          path.write_text(source.replace(needle, replacement, 1))
          PATCH_BPF_DOC
          mkdir -p .nix-dpkg-admin
          : > .nix-dpkg-admin/status
          make -j"$NIX_BUILD_CORES" bindeb-pkg KDEB_PKGVERSION=7.0.0-islands-sgx-1 KDEB_CHANGELOG_DIST=resolute KBUILD_DEBARCH=amd64 DPKG_FLAGS="-d --buildinfo-option=--admindir=$PWD/.nix-dpkg-admin"
          runHook postBuild
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p "$out/packages" "$out/metadata"
          shopt -s nullglob
          debs=(../*.deb)
          test ''${#debs[@]} -gt 0
          cp "''${debs[@]}" "$out/packages/"
          printf '%s\n' "$(cat include/config/kernel.release)" > "$out/metadata/kernel.release"
          cp .config "$out/metadata/config"
          cp System.map "$out/metadata/System.map"
          printf '%s\n' \
            'SYSTEM_TRUSTED_KEYS=certs/ubuntu-canonical-certs.pem' \
            'SYSTEM_REVOCATION_KEYS=certs/ubuntu-canonical-revoked-certs.pem' \
            > "$out/metadata/config-overrides.txt"
          sha256sum certs/ubuntu-canonical-certs.pem certs/ubuntu-canonical-revoked-certs.pem \
            > "$out/metadata/trust-bundles.sha256"
          cp Module.symvers "$out/metadata/Module.symvers"
          sha256sum "$out/metadata/config" > "$out/metadata/config.sha256"
          printf '%s\n' \
            'orig sha256-xjQ3lcjH5P7/VfWzCTZcjg6vSc1qvLQS4yMVMT8UlTY=' \
            'diff sha256-mOkT1KHB+BDk3PpXPLzw8aOkQnvc1QNyJVUpinlMUrI=' \
            'dsc sha256-AW1DV3vYphYpoC4UDjuIBytczdHJDLHOLzyOXCh1bn4=' \
            'debhelper sha256-jogyMuu6dxmbqRZDSnxHDFKLh1e/NEfb/uzy+5XB7ZU=' \
            'libdebhelper-perl sha256-QrrpOK5hOSrqtdMiUWZcCsqu1o3etDlxCEacvescWKY=' \
            > "$out/metadata/source-hashes.txt"
          for deb in "$out"/packages/*.deb; do
            printf '%s\t%s\t%s\n' "$(dpkg-deb -f "$deb" Package)" \
              "$(dpkg-deb -f "$deb" Version)" "$(basename "$deb")"
          done > "$out/metadata/packages.tsv"
          grep -q '^linux-image-' "$out/metadata/packages.tsv"
          grep -q '^linux-headers-' "$out/metadata/packages.tsv"
          runHook postInstall
        '';
        dontStrip = true;
        dontFixup = true;
      };
    in {
      packages.${system} = {
        source = kernelSource;
        kernel-debs = kernelPackages;
        default = kernelPackages;
      };
      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.dpkg pkgs.patch ];
      };
    };
}
