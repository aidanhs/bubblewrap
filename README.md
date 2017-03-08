# machroot

machroot is intended to be a slightly better chroot with self-destruction.
Never run `umount` to tear down a chroot ever again.

You can pronounce it 'mah-chroot' ('my chroot') or 'mach-root' (since it's
faster than chroot at getting you going).

It works by setting up a mount namespace, mounting things as necessary and then
running a command (so possibly dropping you into a shell if that's what you ran).
It may someday support user namespaces to some extent. It will probably never
support anything other than mount namespaces - use a general container system
like runc for that.

You should **never** use it for trying to contain untrusted programs. It is
intended as best-effort filesystem isolation only.

```
$ ./machroot --help
usage: ./machroot [OPTIONS...] COMMAND [ARGS...]

    --help                       Print this help
    --version                    Print version
    --chdir DIR                  Change directory to DIR
    --bind SRC DST               Bind mount the host path SRC on DST
    --dev-bind SRC DST           Bind mount the host path SRC on DST, allowing device access
    --ro-bind SRC DST            Bind mount the host path SRC readonly on DST
    --overlay SRC DST DIR        Mount the host path SRC at DST with an overlayfs
                                 layer on top, using DIR to contain the layer and work dirs
    --remount-ro DST             Remount DST as readonly, it doesn't recursively remount
    --squash DEV DST             Mount DEV squashfs filesystem on DST
    --squash-overlay DEV DST DIR Mount DEV squashfs filesystem on DST with an overlayfs
                                 layer on top, using DIR to contain the layer and work dirs
    --proc DST                   Mount procfs on DST
    --dev DST                    Mount new dev on DST
    --tmpfs DST                  Mount new tmpfs on DST
    --mqueue DST                 Mount new mqueue on DST
```

## Examples

The examples below all involve the user being dropped into a shell.
`(machroot)` has been inserted before the shell prompt to illustrate
when you're inside the environment - they don't appear during normal
usage.

Make sure you have machroot (statically linked and SSL certificates are
embedded, so no deps needed):

```
$ curl -sSL https://github.com/aidanhs/machroot/releases/download/0.1.1/machroot-0.1.1-x86_64-unknown-linux-musl.tar.gz | tar xz
```

### Example 1 - Docker-lite

Example of using machroot as a Docker-lite in combination with
[`dayer`](https://github.com/aidanhs/dayer). Note the evidence of read-only
binds being read-only and tmpfs files vanishing. Running `dayer` with sudo
is not required, but makes sure files are created with the correct permissions.

```
$ curl -sSL https://github.com/aidanhs/dayer/releases/download/v0.2.0/dayer-0.1.0-x86_64-unknown-linux-musl.tar.gz | tar xz
$ sudo ./dayer download-image https://registry-1.docker.io/library/alpine:3.4 alpine
Found 1 blobs
Downloading blob sha256:7095154754192bfc2306f3b2b841ef82771b7ad39526537234adb1e74ae81a93
Extracting blob sha256:7095154754192bfc2306f3b2b841ef82771b7ad39526537234adb1e74ae81a93
Removing sha256:7095154754192bfc2306f3b2b841ef82771b7ad39526537234adb1e74ae81a93
$ sudo ./machroot --bind alpine / --ro-bind /etc /roetc --proc /proc --dev /dev --tmpfs /tmp sh
(machroot) / # ls
bin      etc      lib      media    proc     root     sbin     sys      usr
dev      home     linuxrc  mnt      roetc    run      srv      tmp      var
(machroot) / # touch roetc/x
touch: roetc/x: Read-only file system
(machroot) / # touch tmp/x
(machroot) / # exit
$ ls alpine/tmp/
```

### Example 2 - pristine folder overlay

Example of using machroot to mount a directory with overlayfs, allowing changes
which are saved in a different location and can be picked up again if you
re-enter the environment. Be aware that if the base directory changes, your
modifications may become irrelevant and cause confusion!

`mkdir node` is not strictly required (`machroot` creates target folders for
mountpoints if necessary), but ensures that we don't have a stray empty folder
owned by root. Source files/directories for mounts and overlayfs working
directories *do* need to exist, and here we additionally create the `layer`
directory underneath the overlayfs work dir so the mountpoint is owned by us.

```
$ curl -sSL https://nodejs.org/dist/v7.2.0/node-v7.2.0-linux-x64.tar.gz | tar xz
$ mkdir node
$ mkdir -p overlaywork/layer
$ sudo ./machroot --bind / / --dev-bind /dev /dev --overlay ./node-v7.2.0-linux-x64 $(pwd)/node $(pwd)/overlaywork sudo -u aidanhs bash
(machroot) $ touch node/x
(machroot) $ ls node
bin  CHANGELOG.md  include  lib  LICENSE  README.md  share  x
(machroot) $ exit
$ ls node
$ ls node-v7.2.0-linux-x64
bin  CHANGELOG.md  include  lib  LICENSE  README.md  share
$ sudo ./machroot --bind / / --dev-bind /dev /dev --overlay ./node-v7.2.0-linux-x64 $(pwd)/node $(pwd)/overlaywork sudo -u aidanhs bash
(machroot) $ ls node
bin  CHANGELOG.md  include  lib  LICENSE  README.md  share  x
```

### Example 3 - squashfs disk image modification

Example of using machroot to mount a squashfs disk image, and then using overlayfs
to make the disk image modifiable. Since `mksquashfs` stores the uid/gid of files,
you should potentially use the `-force-uid` and `-force-gid` options to make sure
squashes are created the same way across machines.

```
$ curl -sSL https://nodejs.org/dist/v7.2.0/node-v7.2.0-linux-x64.tar.gz | tar xz
$ mksquashfs node-v7.2.0-linux-x64/ node.squash -noappend -comp xz
[...]
$ rm -r node-v7.2.0-linux-x64/
$ sudo losetup --read-only /dev/loop0 node.squash
$ mkdir node
$ sudo ./machroot --bind / / --dev-bind /dev /dev --squash /dev/loop0 $(pwd)/node sudo -u aidanhs bash
(machroot) $ ls node
bin  CHANGELOG.md  include  lib  LICENSE  README.md  share
(machroot) $ touch node/x
touch: cannot touch 'node/x': Read-only file system
(machroot) $ exit
$ mkdir -p overlaywork/layer
$ sudo ./machroot --bind / / --dev-bind /dev /dev --squash-overlay /dev/loop0 $(pwd)/node ./overlaywork sudo -u aidanhs bash
(machroot) $ touch node/x
(machroot) $ ls -l node/x
-rw-r--r-- 1 aidanhs aidanhs 0 Mar  8 22:40 node/x
(machroot) $ exit
$ ls node
$ ls -l overlaywork/layer/x
-rw-r--r-- 1 aidanhs aidanhs 0 Mar  8 22:40 overlaywork/layer/x
```
