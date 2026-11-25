#!/bin/bash
# mount-and-partition-disk.sh — Split the experiment disk into two equal
# ext4 partitions and mount them.
#
# Run this ON THE NODE as your normal user (it uses sudo where needed):
#
#   ~/736-project/proj-files/scripts/setup/mount-and-partition-disk.sh
#
# Layout created on the disk (default /dev/sdb), GPT:
#
#   partition 1  PARTLABEL=exp-fast  ext4  first 50%   -> mounted at /mnt/fast
#   partition 2  PARTLABEL=exp-slow  ext4  second 50%  -> mounted at /mnt/slow
#
# "slow" is the partition add-dm-delay-to-partition.sh puts a dm-delay
# device on top of; it's a plain partition until that script is run.
#
# Safe to re-run. If the disk already has this layout it is NOT reformatted;
# the script just (re)mounts the partitions. So after a reboot, run this
# again, then add-dm-delay-to-partition.sh. (Nothing is written to
# /etc/fstab on purpose: the dm-delay device doesn't survive a reboot
# either, so both are recreated by re-running the scripts.)
#
# Destructive only when the disk does NOT have the layout yet: it then wipes
# the disk, after asking you to type the disk name (or pass --yes). It
# refuses to touch a disk with mounted partitions, swap, or /, and a disk
# with existing partitions/filesystems needs --force.
#
# Options:
#   --disk <dev>        Disk to partition (default: /dev/sdb)
#   --fast-mnt <dir>    Mount point for partition 1 (default: /mnt/fast)
#   --slow-mnt <dir>    Mount point for partition 2 (default: /mnt/slow)
#   --yes               Don't ask for confirmation before wiping
#   --force             Allow wiping a disk that has other partitions/filesystems
#   --unmount           Unmount both partitions and exit (no changes to the disk)
#   -h, --help          Show this help

set -euo pipefail

PART1_LABEL="exp-fast"
PART2_LABEL="exp-slow"

DISK="/dev/sdb"
FAST_MNT="/mnt/fast"
SLOW_MNT="/mnt/slow"
ASSUME_YES=false
FORCE=false
UNMOUNT_ONLY=false

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk)     DISK="$2"; shift 2 ;;
        --fast-mnt) FAST_MNT="$2"; shift 2 ;;
        --slow-mnt) SLOW_MNT="$2"; shift 2 ;;
        --yes)      ASSUME_YES=true; shift ;;
        --force)    FORCE=true; shift ;;
        --unmount)  UNMOUNT_ONLY=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*"; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] ✗${NC} $*" >&2; exit 1; }

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

# Partitions of $DISK, in order (handles sdb1 and nvme0n1p1 naming).
disk_partitions() { lsblk -lnpo NAME,TYPE "$DISK" | awk '$2 == "part" {print $1}'; }

part_label() { lsblk -dno PARTLABEL "$1" 2>/dev/null; }

# True if $DISK already has exactly our two labelled ext4 partitions.
has_our_layout() {
    local -a parts
    mapfile -t parts < <(disk_partitions)
    [[ ${#parts[@]} -eq 2 ]] &&
    [[ "$(part_label "${parts[0]}")" == "$PART1_LABEL" ]] &&
    [[ "$(part_label "${parts[1]}")" == "$PART2_LABEL" ]] &&
    [[ "$(lsblk -dno FSTYPE "${parts[0]}")" == ext4 ]] &&
    [[ "$(lsblk -dno FSTYPE "${parts[1]}")" == ext4 ]]
}

# Something on the disk is in use: a mounted filesystem, swap, or a
# device-mapper/other holder (e.g. our dm-delay device) on a partition.
disk_in_use() {
    local name mnt holders
    while read -r name mnt; do
        if [[ -n "$mnt" ]]; then
            echo "$name is mounted at $mnt"; return 0
        fi
        holders=$(ls -A "/sys/class/block/$(basename "$name")/holders" 2>/dev/null || true)
        if [[ -n "$holders" ]]; then
            echo "$name is in use by ${holders//$'\n'/ }"; return 0
        fi
    done < <(lsblk -lnpo NAME,MOUNTPOINT "$DISK")
    return 1
}

# Mount $1 at $2 unless it's already mounted there. Skip if a dm device
# sits on top of it (then add-dm-delay-to-partition.sh owns that mount).
mount_part() {
    local dev="$1" mnt="$2" holders
    holders=$(ls -A "/sys/class/block/$(basename "$dev")/holders" 2>/dev/null || true)
    if [[ -n "$holders" ]]; then
        warn "$dev is held by $holders (dm-delay?); not mounting it directly"
        return
    fi
    local cur
    cur=$(findmnt -nro TARGET --source "$dev" 2>/dev/null | head -1 || true)
    if [[ "$cur" == "$mnt" ]]; then
        ok "$dev already mounted at $mnt"
        return
    fi
    [[ -n "$cur" ]] && die "$dev is mounted at $cur, not $mnt; unmount it first"
    if mountpoint -q "$mnt"; then
        die "$mnt already has something else mounted on it"
    fi
    sudo mkdir -p "$mnt"
    sudo mount "$dev" "$mnt"
    # Let experiments write without sudo.
    sudo chown "$(id -u):$(id -g)" "$mnt"
    ok "Mounted $dev ($(part_label "$dev")) at $mnt"
}

unmount_all() {
    local mnt
    for mnt in "$FAST_MNT" "$SLOW_MNT"; do
        if mountpoint -q "$mnt"; then
            sudo umount "$mnt" && ok "Unmounted $mnt"
        else
            log "$mnt not mounted"
        fi
    done
}

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
[[ $EUID -eq 0 ]] && die "Run as your normal user, not root (the script uses sudo where needed)."
[[ -b "$DISK" ]] || die "$DISK is not a block device"
[[ "$(lsblk -dno TYPE "$DISK")" == disk ]] || die "$DISK is not a whole disk (pass e.g. /dev/sdb, not /dev/sdb1)"

if $UNMOUNT_ONLY; then
    unmount_all
    exit 0
fi

# Never touch the disk holding / (belt and braces on top of disk_in_use).
root_src=$(findmnt -nvo SOURCE /)
root_disk=$(lsblk -ndo PKNAME "$root_src" 2>/dev/null || true)
[[ -n "$root_disk" && "/dev/$root_disk" == "$(readlink -f "$DISK")" ]] \
    && die "$DISK holds the root filesystem ($root_src); refusing"

log "Disk: $DISK ($(lsblk -dno SIZE,MODEL "$DISK" | xargs))"

if has_our_layout; then
    ok "$DISK already has the $PART1_LABEL / $PART2_LABEL layout; not reformatting"
else
    if reason=$(disk_in_use); then
        die "$DISK is in use ($reason); refusing to wipe it"
    fi

    existing=$(lsblk -lnpo NAME,FSTYPE,PARTLABEL,SIZE "$DISK" | tail -n +2)
    sig=$(sudo wipefs -n "$DISK" 2>/dev/null || true)
    if [[ -n "$existing" || -n "$sig" ]] && ! $FORCE; then
        warn "$DISK already has data on it:"
        [[ -n "$existing" ]] && printf '    %s\n' "$existing"
        [[ -n "$sig" ]] && printf '%s\n' "$sig"
        die "Refusing to wipe a disk that doesn't have our layout without --force"
    fi

    if ! $ASSUME_YES; then
        warn "This will ERASE everything on $DISK and create 2 equal ext4 partitions."
        read -r -p "Type the disk name ($(basename "$DISK")) to continue: " answer
        [[ "$answer" == "$(basename "$DISK")" ]] || die "Aborted"
    fi

    log "Wiping $DISK and writing a GPT with two equal partitions"
    sudo wipefs -a "$DISK"
    sudo parted -s -a optimal "$DISK" \
        mklabel gpt \
        mkpart "$PART1_LABEL" ext4 0% 50% \
        mkpart "$PART2_LABEL" ext4 50% 100%
    sudo partprobe "$DISK" || true
    sudo udevadm settle

    mapfile -t parts < <(disk_partitions)
    [[ ${#parts[@]} -eq 2 ]] || die "Expected 2 partitions on $DISK after partitioning, found ${#parts[@]}"

    # Initialise inode tables and journal now instead of lazily in the
    # background after mount, so ext4lazyinit doesn't add I/O to the
    # first experiments. Makes mkfs slower (a few minutes on an HDD).
    log "Creating ext4 filesystems (eager init; may take a few minutes)"
    sudo mkfs.ext4 -F -L "$PART1_LABEL" -E lazy_itable_init=0,lazy_journal_init=0 "${parts[0]}"
    sudo mkfs.ext4 -F -L "$PART2_LABEL" -E lazy_itable_init=0,lazy_journal_init=0 "${parts[1]}"
    sudo udevadm settle
    has_our_layout || die "Partitioning finished but the layout check failed; see lsblk -f $DISK"
    ok "Partitioned and formatted $DISK"
fi

mapfile -t parts < <(disk_partitions)
mount_part "${parts[0]}" "$FAST_MNT"
mount_part "${parts[1]}" "$SLOW_MNT"

echo
lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,MOUNTPOINTS "$DISK"
