machroot
========

machroot is intended to be a slightly better chroot with auto-teardown.

You can pronounce it 'mah-chroot' ('my chroot') or 'mach-root' (since it's
faster than chroot at getting you going).

It works by setting up a mount namespace and mounting things as necessary. It
may someday support user namespaces to some extent. It will probably never
support anything other than mount namespaces - use a general container system
like runc for that.

```
usage: ./machroot [OPTIONS...] COMMAND [ARGS...]

    --help                         Print this help
    --version                      Print version
    --chdir DIR                    Change directory to DIR
    --bind SRC DST                 Bind mount the host path SRC on DST
    --dev-bind SRC DST             Bind mount the host path SRC on DST, allowing device access
    --ro-bind SRC DST              Bind mount the host path SRC readonly on DST
    --remount-ro DST               Remount DST as readonly, it doesn't recursively remount
    --squashfs DEV DST             Mount DEV squashfs filesystem on DST
    --squashfs-overlay DEV DST DIR Mount DEV squashfs filesystem on DST with an overlayfs
                                   layer on top, using DIR to contain the layer and work dirs
    --proc DST                     Mount procfs on DST
    --dev DST                      Mount new dev on DST
    --tmpfs DST                    Mount new tmpfs on DST
    --mqueue DST                   Mount new mqueue on DST
```
