#!/bin/bash
# install-kernel.sh - Build, install and boot the cache_ext kernel on a node.
#
# Run this ON THE NODE, from a clone of this repo (e.g. ~/736-project):
#
#   git clone https://github.com/ArjunAnil2000/736-project ~/736-project
#   ~/736-project/proj-files/scripts/setup/install-kernel.sh
#
# The kernel build takes a long time; run it inside tmux/screen so an SSH
# drop doesn't kill it. Output is also appended to ~/install-kernel.log.
#
# The script is staged and safe to re-run. It looks at the node's state and
# does the next thing that's needed:
#
#   Stage 1 (running stock kernel, cache_ext kernel not installed):
#     switch apt to https, init submodules, build + install the cache_ext
#     kernel, then grub-reboot into it (one-shot) and reboot.
#   Stage 1b (running stock kernel, cache_ext kernel already installed):
#     skip the build, just grub-reboot into it and reboot.
#   Stage 2 (running the cache_ext kernel):
#     install benchmark tools and build the cache_ext policies.
#
# So the usual flow is: run it, wait for the reboot, SSH back in, run it again.
#
# Note: grub-reboot is one-shot. If the node reboots again it comes back on
# the stock kernel; re-running this script boots back into cache_ext.
#
# Options:
#   --no-reboot         Don't reboot after installing (print the command instead)
#   --rebuild           Rebuild + reinstall the kernel even if it's installed
#   --skip-space-check  Don't check for free disk space before building
#   --skip-apt-https    Don't rewrite apt sources from http:// to https://
#   -h, --help          Show this help

set -euo pipefail

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
KERNEL_TAG="6.6.8-cache-ext+"
GRUB_ENTRY="Advanced options for Ubuntu>Ubuntu, with Linux ${KERNEL_TAG}"
MIN_FREE_GB=35
LOG_FILE="$HOME/install-kernel.log"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
PROJ_DIR="$REPO_ROOT/proj-files"
CACHE_EXT_DIR="$PROJ_DIR/cache_ext"

# ------------------------------------------------------------------
# Options
# ------------------------------------------------------------------
NO_REBOOT=false
REBUILD=false
SKIP_SPACE_CHECK=false
SKIP_APT_HTTPS=false

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-reboot)        NO_REBOOT=true; shift ;;
        --rebuild)          REBUILD=true; shift ;;
        --skip-space-check) SKIP_SPACE_CHECK=true; shift ;;
        --skip-apt-https)   SKIP_APT_HTTPS=true; shift ;;
        -h|--help)          usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
exec > >(tee -a "$LOG_FILE") 2>&1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*"; exit 1; }

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
running_cache_ext() { [[ "$(uname -r)" == *cache-ext* ]]; }

kernel_installed() {
    [[ -e "/boot/vmlinuz-${KERNEL_TAG}" ]] &&
        sudo grep -qF "with Linux ${KERNEL_TAG}'" /boot/grub/grub.cfg
}

# Some CloudLab sites (e.g. wisc.cloudlab.us) block outbound plain HTTP but
# allow HTTPS. apt's default sources are http://, which then hang on every
# apt-get call. Rewrite them once. Covers both the classic one-line format
# (*.list, Ubuntu <= 22.04) and the deb822 format (*.sources, Ubuntu 24.04+).
apt_use_https() {
    if $SKIP_APT_HTTPS; then
        log "Skipping apt http -> https rewrite (--skip-apt-https)"
        return
    fi
    log "Switching apt sources to https"
    local f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [[ -f "$f" ]] && sudo sed -i 's#http://#https://#g' "$f"
    done
    sudo apt-get update
    ok "apt sources use https"
}

check_free_space() {
    if $SKIP_SPACE_CHECK; then
        warn "Skipping free-space check (--skip-space-check)"
        return
    fi
    # The build tree lives under the repo; modules/kernel install to / (/lib, /boot).
    local path avail_gb
    for path in "$REPO_ROOT" /; do
        avail_gb=$(df -BG --output=avail "$path" | tail -1 | tr -dc '0-9')
        if (( avail_gb < MIN_FREE_GB )); then
            die "Only ${avail_gb}G free on $(df --output=target "$path" | tail -1) (for $path); need ~${MIN_FREE_GB}G for the kernel build. Use --skip-space-check to override."
        fi
        log "Free space for $path: ${avail_gb}G (need ${MIN_FREE_GB}G)"
    done
}

init_submodules() {
    log "Initialising submodules (includes the cache_ext linux tree; this is large)"
    git -C "$REPO_ROOT" submodule update --init --recursive
    ok "Submodules initialised"
}

build_and_install_kernel() {
    log "Building + installing the cache_ext kernel (this takes a while)"
    # build.py builds with CC="ccache clang"; cache_ext's install_kernel.sh
    # doesn't install ccache, so make sure it's present.
    sudo apt-get install -y ccache
    # Auto-answer install_kernel.sh's interactive prompts: 1, Y, 1, N
    # (carried over unchanged from the mem-evolve setup, where this worked).
    (cd "$CACHE_EXT_DIR" && printf '1\nY\n1\nN\n' | bash ./install_kernel.sh) \
        || die "cache_ext install_kernel.sh failed"
    kernel_installed || die "Build finished but no '${KERNEL_TAG}' entry found in /boot/grub/grub.cfg"
    ok "cache_ext kernel installed"
}

reboot_into_cache_ext() {
    sudo grub-reboot "$GRUB_ENTRY" || die "grub-reboot failed"
    ok "Next boot (one-shot) set to: $GRUB_ENTRY"
    if $NO_REBOOT; then
        warn "--no-reboot given. Reboot when ready with: sudo reboot"
        warn "Then re-run this script to finish setup (stage 2)."
        exit 0
    fi
    log "Rebooting now. SSH back in once the node is up and re-run:"
    log "    $SCRIPT_DIR/install-kernel.sh"
    sudo reboot
    exit 0
}

# Run one of cache_ext's helper scripts unless its output already exists.
# install_filesearch.sh and setup_isolation.sh `git clone` into fixed paths and
# fail if those exist, so they need this guard to make re-runs safe.
run_once() {
    local marker="$1" script="$2"
    if [[ -n "$marker" && -e "$marker" ]]; then
        ok "$script: already done ($marker exists), skipping"
        return
    fi
    log "Running $script"
    (cd "$CACHE_EXT_DIR" && bash "./$script") || die "$script failed"
    ok "$script done"
}

post_reboot_setup() {
    log "Stage 2: running $(uname -r); installing tools + building policies"
    # These clone/build into proj-files/ (paths are relative to cache_ext/).
    run_once "$PROJ_DIR/linux/.git"        install_filesearch.sh
    run_once ""                            install_misc.sh
    run_once "$PROJ_DIR/cgroup/linux/.git" setup_isolation.sh
    run_once ""                            build_policies.sh
    ok "Node ready: cache_ext kernel running and policies built in $CACHE_EXT_DIR/policies"
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
[[ $EUID -eq 0 ]] && die "Run as your normal user, not root (the script uses sudo where needed)."
[[ -d "$CACHE_EXT_DIR" ]] || die "cache_ext submodule path not found: $CACHE_EXT_DIR"

log "Repo: $REPO_ROOT"
log "Running kernel: $(uname -r)"
log "Log file: $LOG_FILE"

if running_cache_ext && ! $REBUILD; then
    post_reboot_setup
    exit 0
fi

if kernel_installed && ! $REBUILD; then
    log "Stage 1b: cache_ext kernel already installed; booting into it"
    reboot_into_cache_ext
fi

log "Stage 1: building and installing the cache_ext kernel"
apt_use_https
check_free_space
init_submodules
build_and_install_kernel
reboot_into_cache_ext
