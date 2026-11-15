---
title: Cloudlab node access and setup
author: Arjun Anil
---

# ssh access to node

Hit Arjun up for this.

# How to install cache_ext

1. Clone the repo into the host in question.
2. Make a new tmux/screen since compiling and installing the kernel would take time.
3. Run `$REPO_ROOT/proj-files/scripts/setup/install-cache-ext.sh`
4. Wait for this to finish. The script should reboot the host into the cache_ext kernel when it's
   done.
5. The reboot should have dropped the ssh connection, login using ssh again.
6. Run the script again i.e `$REPO_ROOT/proj-files/scripts/setup/install-cache-ext.sh`. This installs some
   deps that need to be installed post cache-ext bootup.

# How to partition the disk

1. Run the partition script -- `$REPO_ROOT/proj-files/scripts/setup/mount-and-partition-disk.sh`

> [!IMPORTANT]
> The script checks if the disk in question has already been partitioned. 
> If not, the disk in question will be formatted before being partitioned.
> Double check the correct disk.

> [!NOTE]
> Disk being partitioned.  
> The cloudlab instances usually have `sdb` free, so it's assumed `/dev/sdb` is the disk being
> partitioned. If required, there's an option to pass a disk path. Use `--help` to see all options.

# How to add dm-delay

1. Run the `dm-delay` script -- `$REPO_ROOT/proj-files/scripts/setup/add-dm-delay-to-partition.sh`

> [!NOTE]
> `dm-delay` quirk  
> `dm-delay` does not persist with reboots. So if the host is rebooted, the `dm-delay` script will
> need to be re-run.
