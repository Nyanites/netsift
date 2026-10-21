#!/bin/sh
# NetSift installer for macOS and Linux.
#
#   curl -fsSL https://nyanites.github.io/netsift/install.sh | sh
#
# What it does, in order:
#   1. Downloads the latest NetSift release for your OS and CPU, and its
#      SHA256SUMS.txt, from https://github.com/Nyanites/netsift/releases
#   2. Checks the download against the published SHA-256 checksum and stops if it
#      doesn't match.
#   3. macOS: copies NetSift.app into /Applications (or ~/Applications if
#      /Applications isn't writable), replacing an older NetSift.app there.
#      Linux: installs the program to ~/.local/bin/netsift and adds a menu entry.
#   4. Checks whether live capture will work (packet capture permission, libpcap)
#      and, if not, prints the one command that fixes it. It doesn't run it.
#   5. Cleans up its temporary files.
#
# It never asks for your password and changes nothing else on your computer.
#
# Options (environment variables):
#   NETSIFT_VERSION=0.1.0       install a specific release instead of the latest
#   NETSIFT_INSTALL_DIR=<dir>   install somewhere else
#
# Uninstall:
#   macOS: drag NetSift from Applications to the Trash.
#   Linux: rm ~/.local/bin/netsift ~/.local/share/applications/netsift.desktop \
#             ~/.local/share/icons/hicolor/256x256/apps/netsift.png
#
# Source: https://github.com/Nyanites/netsift/blob/main/docs/install.sh

NS_TMP=""

ns_cleanup() {
    if [ -n "$NS_TMP" ] && [ -d "$NS_TMP" ]; then
        rm -rf "$NS_TMP"
    fi
}

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

fetch() {
    curl -fL --proto '=https' --tlsv1.2 --retry 3 "$@"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

# Downloads release asset $1 into the temp dir and verifies it.
download() {
    say "Downloading $1"
    fetch --progress-bar -o "$NS_TMP/$1" "$base/$1" || fail "download failed"
    expected=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$NS_TMP/SHA256SUMS.txt")
    [ -n "$expected" ] || fail "checksum for $1 not found in SHA256SUMS.txt"
    actual=$(sha256 "$NS_TMP/$1")
    [ "$expected" = "$actual" ] || fail "checksum mismatch for $1 (expected $expected, got $actual); not installing"
}

install_macos() {
    command -v ditto >/dev/null || fail "missing required tool: ditto"
    major=$(sw_vers -productVersion | cut -d. -f1)
    [ "$major" -ge 11 ] 2>/dev/null || fail "NetSift needs macOS 11 or newer."
    app="NetSift.app"
    dest="${NETSIFT_INSTALL_DIR:-/Applications}"
    if [ -z "${NETSIFT_INSTALL_DIR:-}" ] && [ ! -w "$dest" ]; then
        dest="$HOME/Applications"
    fi
    mkdir -p "$dest"
    [ -w "$dest" ] || fail "can't write to $dest"

    download NetSift-macos.zip
    say "Installing to $dest"
    mkdir -p "$NS_TMP/unpacked"
    ditto -x -k "$NS_TMP/NetSift-macos.zip" "$NS_TMP/unpacked" || fail "couldn't unpack the download"
    [ -d "$NS_TMP/unpacked/$app" ] || fail "$app not found in the download"
    if pgrep -xq netsift; then
        say "Quitting the running NetSift"
        osascript -e 'quit app "NetSift"' >/dev/null 2>&1 || true
        sleep 1
    fi
    # Replace only an existing NetSift.app, never anything else.
    if [ -d "$dest/$app" ]; then
        rm -rf "${dest:?}/$app"
    fi
    ditto "$NS_TMP/unpacked/$app" "$dest/$app"
    say "NetSift is installed in $dest"
    printf '    Open it from Launchpad or Applications, then open a capture or start capturing.\n'
    # Live capture reads /dev/bpf*, which macOS only lets root use unless a helper
    # (Wireshark's ChmodBPF) opened it to the access_bpf group.
    if [ ! -r /dev/bpf0 ]; then
        printf '\n    Live capture needs access to /dev/bpf*. Opening capture files works without it.\n'
        printf '    If Wireshark is installed, its ChmodBPF helper does this. Or, until the next restart:\n'
        printf '        sudo chmod o+r /dev/bpf*\n'
    fi
}

install_linux() {
    case "$(uname -m)" in
        x86_64 | amd64) asset=netsift-linux-x86_64 ;;
        aarch64 | arm64) asset=netsift-linux-arm64 ;;
        *) fail "no Linux build for $(uname -m); build from source: https://github.com/Nyanites/netsift" ;;
    esac
    bindir="${NETSIFT_INSTALL_DIR:-$HOME/.local/bin}"
    data="${XDG_DATA_HOME:-$HOME/.local/share}"
    mkdir -p "$bindir" "$data/applications" "$data/icons/hicolor/256x256/apps"
    [ -w "$bindir" ] || fail "can't write to $bindir"

    download "$asset"
    download netsift.png
    say "Installing to $bindir"
    # Install via a temp name in the same directory, then rename: replaces a running copy safely.
    cp "$NS_TMP/$asset" "$bindir/.netsift.new"
    chmod 755 "$bindir/.netsift.new"
    mv -f "$bindir/.netsift.new" "$bindir/netsift"
    cp "$NS_TMP/netsift.png" "$data/icons/hicolor/256x256/apps/netsift.png"
    cat > "$data/applications/netsift.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetSift
GenericName=Packet Analyzer
Comment=Capture, decrypt and analyze network traffic
Exec="$bindir/netsift" %F
Icon=netsift
Terminal=false
Categories=Network;Utility;Security;
MimeType=application/vnd.tcpdump.pcap;application/x-pcapng;
EOF
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$data/applications" >/dev/null 2>&1 || true

    say "NetSift is installed: $bindir/netsift"
    case ":$PATH:" in
        *":$bindir:"*) printf '    Start it from your app menu or run: netsift\n' ;;
        *) printf '    Start it from your app menu, or add %s to your PATH to run: netsift\n' "$bindir" ;;
    esac
    # NetSift uses the system libpcap for capture files and live capture.
    if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so\.0\.8'; then
        printf '\n    NetSift needs libpcap. Install it with your package manager, e.g.:\n'
        printf '        sudo apt install libpcap0.8      (Debian, Ubuntu)\n'
        printf '        sudo dnf install libpcap         (Fedora)\n'
    fi
    printf '\n    Live capture needs packet-capture permission. Grant it once, without running as root:\n'
    printf '        sudo setcap cap_net_raw,cap_net_admin=eip %s/netsift\n' "$bindir"
}

# Everything runs inside main(), called on the last line, so a partially downloaded
# script does nothing.
main() {
    set -eu
    repo="Nyanites/netsift"
    for tool in curl awk uname; do
        command -v "$tool" >/dev/null || fail "missing required tool: $tool"
    done
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 \
        || fail "missing required tool: sha256sum or shasum"

    if [ -n "${NETSIFT_VERSION:-}" ]; then
        case "$NETSIFT_VERSION" in
            *[!0-9A-Za-z.-]*) fail "invalid NETSIFT_VERSION: $NETSIFT_VERSION" ;;
        esac
        base="https://github.com/$repo/releases/download/v${NETSIFT_VERSION#v}"
    else
        base="https://github.com/$repo/releases/latest/download"
    fi

    NS_TMP=$(mktemp -d "${TMPDIR:-/tmp}/netsift-install.XXXXXX")
    trap ns_cleanup EXIT
    trap 'exit 1' INT TERM
    fetch -sS -o "$NS_TMP/SHA256SUMS.txt" "$base/SHA256SUMS.txt" \
        || fail "couldn't download the checksum file"

    case "$(uname -s)" in
        Darwin) install_macos ;;
        Linux) install_linux ;;
        *) fail "this installer runs on macOS and Linux; Windows support is coming (needs Npcap)" ;;
    esac
}

main "$@"
