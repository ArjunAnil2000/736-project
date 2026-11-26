#!/bin/bash
# add-dm-delay-to-partition.sh — Put a dm-delay device on top of a partition
# so every I/O to it gets a fixed extra latency, and mount it.
#
# Run this ON THE NODE as your normal user (it uses sudo where needed),
# after mount-and-partition-disk.sh:
#
#   ~/736-project/proj-files/scripts/setup/add-dm-delay-to-partition.sh --read-ms 5
#
# By default it targets the "slow" partition (PARTLABEL=exp-slow) created by
# mount-and-partition-disk.sh and mounts the delayed device at /mnt/slow,
# in place of the raw partition:
#
#   /dev/sdb2 (exp-slow) --> /dev/mapper/exp-slow-delay --> /mnt/slow
#
# The filesystem is the same either way (the mapping is 1:1, offset 0), so
# files written before or after adding the delay are all still there.
#
# Behaviour:
#   - No delay device yet: unmounts the raw partition, creates the device,
#     mounts the device at the mount point.
#   - Delay device exists: changes the delay in place (dmsetup reload +
#     resume). No unmount needed, open files stay open.
#   - --remove: unmounts the device, removes it, remounts the raw partition.
#
# Device-mapper tables live only in memory, so after a reboot run
# mount-and-partition-disk.sh and then this script again.
#
# Options:
#   --read-ms <ms>      Delay added to every read, in ms (required unless --remove/--status)
#   --write-ms <ms>     Delay added to every write, in ms (default: same as --read-ms)
#   --part <dev>        Partition to delay (default: /dev/disk/by-partlabel/exp-slow)
#   --name <name>       Device-mapper name (default: exp-slow-delay)
#   --mnt <dir>         Mount point (default: /mnt/slow)
#   --remove            Remove the delay device and remount the raw partition
#   --status            Show the current delay device table and mount, then exit
#   -h, --help          Show this help

set -euo pipefail

PART="/dev/disk/by-partlabel/exp-slow"
DM_NAME="exp-slow-delay"
MNT="/mnt/slow"
READ_MS=""
WRITE_MS=""
REMOVE=false
STATUS=false

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --read-ms)  READ_MS="$2"; shift 2 ;;
        --write-ms) WRITE_MS="$2"; shift 2 ;;
        --part)     PART="$2"; shift 2 ;;
        --name)     DM_NAME="$2"; shift 2 ;;
        --mnt)      MNT="$2"; shift 2 ;;
        --remove)   REMOVE=true; shift ;;
        --status)   STATUS=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*" >&2; exit 1; }

DM_DEV="/dev/mapper/$DM_NAME"

dm_exists() { sudo dmsetup info "$DM_NAME" &>/dev/null; }

# Device currently mounted at $MNT (empty if none).
mounted_src() { findmnt -nro SOURCE --mountpoint "$MNT" 2>/dev/null || true; }

# True if $1 (a device path) is what's mounted at $MNT.
mounted_here() {
    local src
    src=$(mounted_src)
    [[ -n "$src" ]] && [[ "$(readlink -f "$src")" == "$(readlink -f "$1")" ]]
}

do_mount() {
    local dev="$1"
    if mounted_here "$dev"; then
        ok "$dev already mounted at $MNT"
        return
    fi
    [[ -n "$(mounted_src)" ]] && die "$MNT has $(mounted_src) mounted on it, expected $dev"
    sudo mkdir -p "$MNT"
    sudo mount "$dev" "$MNT"
    sudo chown "$(id -u):$(id -g)" "$MNT"
    ok "Mounted $dev at $MNT"
}

# If $1 is mounted at $MNT, unmount it.
do_umount() {
    local dev="$1"
    if mounted_here "$dev"; then
        sync
        sudo umount "$MNT" || die "Couldn't unmount $MNT (something using it? try: sudo fuser -vm $MNT)"
        ok "Unmounted $dev from $MNT"
    fi
}

show_status() {
    if dm_exists; then
        log "Table for $DM_NAME (start len delay <dev> <offset> <read_ms> [<dev> <offset> <write_ms>]):"
        sudo dmsetup table "$DM_NAME" | sed 's/^/    /'
    else
        log "No device-mapper device named $DM_NAME"
    fi
    log "Mounted at $MNT: $(mounted_src || true)"
    [[ -z "$(mounted_src)" ]] && log "    (nothing)"
    return 0
}

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
[[ $EUID -eq 0 ]] && die "Run as your normal user, not root (the script uses sudo where needed)."

if $STATUS; then
    show_status
    exit 0
fi

[[ -e "$PART" ]] || die "Partition $PART not found (run mount-and-partition-disk.sh first?)"
PART_DEV=$(readlink -f "$PART")
[[ "$(lsblk -dno TYPE "$PART_DEV")" == part ]] || die "$PART ($PART_DEV) is not a partition"

if $REMOVE; then
    if dm_exists; then
        do_umount "$DM_DEV"
        sudo dmsetup remove "$DM_NAME"
        ok "Removed $DM_NAME"
    else
        log "No $DM_NAME device to remove"
    fi
    do_mount "$PART_DEV"
    exit 0
fi

[[ -n "$READ_MS" ]] || die "--read-ms is required (e.g. --read-ms 5)"
[[ -n "$WRITE_MS" ]] || WRITE_MS="$READ_MS"
is_uint "$READ_MS"  || die "--read-ms must be a whole number of milliseconds, got '$READ_MS'"
is_uint "$WRITE_MS" || die "--write-ms must be a whole number of milliseconds, got '$WRITE_MS'"

# dm-delay must be available in the running kernel (built in or as a module).
if ! grep -qw delay <(sudo dmsetup targets); then
    sudo modprobe dm_delay 2>/dev/null || true
    grep -qw delay <(sudo dmsetup targets) \
        || die "dm-delay target not available in kernel $(uname -r) (check CONFIG_DM_DELAY in /boot/config-$(uname -r))"
fi

SECTORS=$(sudo blockdev --getsz "$PART_DEV")
# Separate read and write delays: "delay <dev> <off> <read_ms> <dev> <off> <write_ms>".
TABLE="0 $SECTORS delay $PART_DEV 0 $READ_MS $PART_DEV 0 $WRITE_MS"

log "Partition: $PART -> $PART_DEV ($SECTORS sectors)"
log "Delay: read ${READ_MS} ms, write ${WRITE_MS} ms"

if dm_exists; then
    # Swap the table in place; I/O is paused only for the switch.
    log "$DM_NAME exists; updating its delay in place"
    sudo dmsetup reload "$DM_NAME" --table "$TABLE"
    sudo dmsetup resume "$DM_NAME"
    ok "Updated $DM_NAME"
    do_mount "$DM_DEV"
else
    # The raw partition and the dm device must not both be mounted.
    do_umount "$PART_DEV"
    [[ -n "$(findmnt -nro TARGET --source "$PART_DEV" 2>/dev/null || true)" ]] \
        && die "$PART_DEV is still mounted at $(findmnt -nro TARGET --source "$PART_DEV" | head -1); unmount it first"
    sudo dmsetup create "$DM_NAME" --table "$TABLE"
    sudo udevadm settle
    ok "Created $DM_DEV"
    do_mount "$DM_DEV"
fi

show_status
