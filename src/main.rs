#![feature(const_fn)]
#![feature(field_init_shorthand)]
#![feature(slice_patterns)]

#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate nix;

use std::ffi::{CStr, CString};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::unix::fs as unixfs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path;
use std::path::{Path, PathBuf};
use std::process;
use std::ptr;
use std::str;
use std::sync::Mutex;

use libc::{c_char, c_int};

use nix::mount as nixmount;
use nix::mount::{mount, umount2};

use SetupOp::*;

type BindOption = u32;
const BIND_READONLY: BindOption = (1 << 0);
const BIND_DEVICES: BindOption = (1 << 2);
const BIND_RECURSIVE: BindOption = (1 << 3);

#[derive(Eq, PartialEq)]
pub enum SetupOp {
    BindMount(PathBuf, PathBuf), // src, dst
    ROBindMount(PathBuf, PathBuf), // src, dst
    DevBindMount(PathBuf, PathBuf), // src, dst
    MountSquash(PathBuf, PathBuf), // loopdev, dst
    MountSquashOverlay(PathBuf, PathBuf, PathBuf), // loopdev, dst, overlaydir
    MountProc(PathBuf), // dst
    MountDev(PathBuf), // dst
    MountTmpfs(PathBuf), // dst
    MountMQueue(PathBuf), // dst
    RemountRONoRecursive(PathBuf), // dst
}

// TODO: not really
unsafe impl Send for SetupOp {}

const PACKAGE_STRING: &'static str = "machroot 0.1.0";

#[no_mangle]
pub static mut opt_chdir_path: *const c_char = ptr::null();
#[no_mangle]
pub static mut proc_fd: c_int = -1;
#[no_mangle]
pub static mut host_tty_dev: *const c_char = ptr::null();

lazy_static! {
    static ref OPS: Mutex<Vec<SetupOp>> = Mutex::new(vec![]);
}

#[no_mangle]
pub extern "C" fn setup_op_new(op: SetupOp) {
    OPS.lock().unwrap().push(op);
}

fn join_suffix<P: AsRef<Path>>(path: &Path, suffix: P) -> PathBuf {
    let suffixpath = suffix.as_ref();
    let mut components = suffixpath.components();
    if suffixpath.has_root() {
        assert_eq!(components.next(), Some(path::Component::RootDir));
    }
    path.join(components)
}

fn mkdir(path: &Path, mode: u32) -> Option<io::Error> {
    DirBuilder::new().mode(mode).create(path).err()
}
fn mkdirall(path: &Path, mode: u32) -> Option<io::Error> {
    DirBuilder::new().recursive(true).mode(mode).create(path).err()
}
fn create_file(path: &Path, mode: u32) -> Option<io::Error> {
    OpenOptions::new().mode(mode).write(true).create_new(true).open(path).err()
}

// NOTE: these try to avoid symlinks but doesn't do very well
// NOTE: we check existence ahead of time, otherwise the create
// file will fail in the read-only case with EROFS instead of EEXIST
fn ensure_dirs(path: &Path, mode: u32) -> Option<io::Error> {
    if let Ok(m) = path.metadata() { if m.is_dir() { return None } }
    mkdirall(path, mode)
}
fn ensure_dir(path: &Path, mode: u32) -> Option<io::Error> {
    if let Ok(m) = path.metadata() { if m.is_dir() { return None } }
    mkdir(path, mode)
}
fn ensure_file(path: &Path, mode: u32) -> Option<io::Error> {
    if let Ok(m) = path.metadata() { if m.is_file() { return None } }
    create_file(path, mode)
}

unsafe fn ptr_to_path(ptr: *const c_char) -> PathBuf {
    PathBuf::from(CStr::from_ptr(ptr).to_str().unwrap())
}
fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.to_str().unwrap()).unwrap()
}

#[no_mangle]
pub extern "C" fn setup_newroot() {
    let mut ops = OPS.lock().unwrap();
    let mut uniq_count = 0;

    // Musl needs /proc to do realpath - https://github.com/alexcrichton/tar-rs/issues/94
    {
        if let Some(err) = mkdir(Path::new("/proc"), 0o755) {
            panic!("Can't create dir for temporary proc: {}", err)
        }
        let flags = nixmount::MS_MGC_VAL | nixmount::MS_NOSUID | nixmount::MS_NOEXEC | nixmount::MS_NODEV;
        if let Err(err) = mount::<_, _, _, Path>(Some("proc"), "/proc", Some("proc"), flags, None) {
            panic!("Can't mount temporary proc: {}", err)
        }
    }

    for op in ops.drain(..) {

        fn prepare_src(src: &Path) -> (PathBuf, &str) {
            let path = join_suffix(Path::new("/oldroot/"), src);
            (path, src.to_str().unwrap())
        }

        fn prepare_dst(dst: &Path) -> (PathBuf, &str) {
            let path = join_suffix(Path::new("/newroot/"), &dst);
            let mut parents = path.clone();
            parents.pop();
            if let Some(err) = ensure_dirs(&parents, 0o755) {
                panic!("Can't mkdir parents for {}: {}", dst.to_str().unwrap(), err)
            }
            (path, dst.to_str().unwrap())
        }

        let bindflags = match op {
            ROBindMount(_, _) => BIND_READONLY,
            DevBindMount(_, _) => BIND_DEVICES,
            _ => 0,
        };
        match op {
            ROBindMount(src, dst) |
            DevBindMount(src, dst) |
            BindMount(src, dst) => {
                let (ref src, op_src) = prepare_src(&src);
                let (ref dst, op_dst) = prepare_dst(&dst);
                let src_isdir = match src.metadata() {
                    Ok(metadata) => metadata.is_dir(),
                    Err(err) => panic!("Can't get type of source {}: {}", op_src, err),
                };
                if src_isdir {
                    if let Some(err) = ensure_dir(dst, 0o755) {
                        panic!("Can't mkdir {}: {}", op_dst, err)
                    }
                } else if let Some(err) = ensure_file(dst, 0o666) {
                    panic!("Can't create file at {}: {}", op_dst, err)
                }

                let (c_src, c_dst) = (path_to_cstring(src), path_to_cstring(dst));
                if unsafe { bind_mount(proc_fd, c_src.as_ptr(), c_dst.as_ptr(), BIND_RECURSIVE | bindflags) } != 0 {
                    panic!("Can't bind mount {} on {}", src.to_str().unwrap(), dst.to_str().unwrap())
                }
            },
            MountSquash(src, dst) => {
                let (ref src, op_src) = prepare_src(&src);
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }
                check_loop_device(src);
                let flags = nixmount::MS_MGC_VAL | nixmount::MS_RDONLY;
                if let Err(err) = mount::<_, _, _, Path>(Some(src), dst, Some("squashfs"), flags, None) {
                    panic!("Can't mount squashfs {} on {}: {}", op_src, op_dst, err)
                }
            },
            MountSquashOverlay(src, dst, overlaydir) => {
                let (ref src, op_src) = prepare_src(&src);
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }
                let overlaydir = &join_suffix(Path::new("/oldroot/"), overlaydir);
                let squashmount = &PathBuf::from(format!("/uniqsquash_{}", uniq_count));
                uniq_count += 1;
                let layerdir = &join_suffix(overlaydir, "layer");
                let workdir = &join_suffix(overlaydir, "work");
                if let Some(err) = mkdir(squashmount, 0o755) {
                    panic!("Can't mkdir {}: {}", squashmount.to_str().unwrap(), err)
                }
                if let Some(err) = ensure_dir(layerdir, 0o755) {
                    panic!("Can't mkdir {}: {}", layerdir.to_str().unwrap(), err)
                }
                if let Some(err) = ensure_dir(workdir, 0o755) {
                    panic!("Can't mkdir {}: {}", workdir.to_str().unwrap(), err)
                }
                check_loop_device(src);
                let flags = nixmount::MS_MGC_VAL | nixmount::MS_RDONLY;
                if let Err(err) = mount::<_, _, _, Path>(Some(src), squashmount, Some("squashfs"), flags, None) {
                    panic!("Can't mount squashfs {} on {}: {}", op_src, op_dst, err)
                }
                let opts: &str = &format!("lowerdir={},upperdir={},workdir={}", squashmount.to_str().unwrap(), layerdir.to_str().unwrap(), workdir.to_str().unwrap());
                if let Err(err) = mount(Some("overlay"), dst, Some("overlay"), nixmount::MS_MGC_VAL, Some(opts)) {
                    panic!("Can't mount overlayfs on {}: {}", op_dst, err)
                }
            },
            RemountRONoRecursive(dst) => {
                let (ref dst, _op_dst) = prepare_dst(&dst);
                let c_dst = path_to_cstring(dst);
                if unsafe { bind_mount(proc_fd, ptr::null(), c_dst.as_ptr(), BIND_READONLY) } != 0 {
                    panic!("Can't remount readonly on {}", dst.to_str().unwrap())
                }
            },
            MountProc(dst) => {
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }
                let flags = nixmount::MS_MGC_VAL | nixmount::MS_NOSUID | nixmount::MS_NOEXEC | nixmount::MS_NODEV;
                if let Err(err) = mount::<_, _, _, Path>(Some("proc"), dst, Some("proc"), flags, None) {
                    panic!("Can't mount proc on {}: {}", dst.to_str().unwrap(), err)
                }
            },
            MountDev(dst) => {
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }

                let flags = nixmount::MS_MGC_VAL | nixmount::MS_NOSUID | nixmount::MS_NODEV;
                if let Err(err) = mount(Some("tmpfs"), dst, Some("tmpfs"), flags, Some("mode=0755")) {
                    panic!("Can't mount tmpfs on {}: {}", op_dst, err)
                }

                const DEVNODES: &'static [&'static str] = &["null", "zero", "full", "random", "urandom", "tty"];
                for &node in DEVNODES.iter() {
                    let node_dst = &join_suffix(dst, node);
                    let node_src = &join_suffix(&PathBuf::from("/oldroot/dev/"), node);
                    if let Some(err) = create_file(node_dst, 0o666) {
                        panic!("Can't create file {}/{}: {}", op_dst, node, err)
                    }
                    let (c_node_src, c_node_dst) = (path_to_cstring(node_src), path_to_cstring(node_dst));
                    if unsafe { bind_mount(proc_fd, c_node_src.as_ptr(), c_node_dst.as_ptr(), BIND_RECURSIVE | BIND_DEVICES) } != 0 {
                        panic!("Can't bind mount {} on {}", node_src.to_str().unwrap(), node_dst.to_str().unwrap())
                    }
                }

                const STDIONODES: &'static [&'static str] = &["stdin", "stdout", "stderr"];
                for (i, &node) in STDIONODES.iter().enumerate() {
                    let target = &join_suffix(&PathBuf::from("/proc/self/fd"), i.to_string());
                    let node_dst = &join_suffix(dst, node);
                    if let Err(err) = unixfs::symlink(target, node_dst) {
                        panic!("Can't create symlink {}/{}: {}", op_dst, node, err)
                    }
                }

                let pts = &join_suffix(dst, "pts");
                let ptmx = &join_suffix(dst, "ptmx");
                let shm = &join_suffix(dst, "shm");

                if let Some(err) = mkdir(shm, 0o755) {
                    panic!("Can't create {}/shm: {}", op_dst, err)
                }

                if let Some(err) = mkdir(pts, 0o755) {
                    panic!("Can't create {}/pts: {}", op_dst, err)
                }
                let flags = nixmount::MS_MGC_VAL | nixmount::MS_NOSUID | nixmount::MS_NOEXEC;
                if let Err(err) = mount(Some("devpts"), pts, Some("devpts"), flags, Some("newinstance,ptmxmode=0666,mode=620")) {
                    panic!("Can't mount devpts on {}: {}", pts.to_str().unwrap(), err)
                }

                if let Err(err) = unixfs::symlink("pts/ptmx", ptmx) {
                    panic!("Can't make symlink at {}/ptmx: {}", op_dst, err)
                }

                // If stdout is a tty, that means the sandbox can write to the
                // outside-sandbox tty. In that case we also create a /dev/console
                // that points to this tty device. This should not cause any more
                // access than we already have, and it makes ttyname() work in the
                // sandbox.
                if unsafe { host_tty_dev != ptr::null() && *host_tty_dev != 0 } {
                    let src_tty_dev = &join_suffix(&PathBuf::from("/oldroot"), unsafe { CStr::from_ptr(host_tty_dev).to_str().unwrap() });
                    let dst_console = &join_suffix(dst, "console");

                    if let Some(err) = create_file(dst_console, 0o666) {
                        panic!("creating {}/console: {}", op_dst, err)
                    }

                    let (c_src_tty_dev, c_dst_console) = (path_to_cstring(src_tty_dev), path_to_cstring(dst_console));
                    if unsafe { bind_mount(proc_fd, c_src_tty_dev.as_ptr(), c_dst_console.as_ptr(), BIND_RECURSIVE | BIND_DEVICES) } != 0 {
                        panic!("Can't bind mount {} on {}", src_tty_dev.to_str().unwrap(), dst_console.to_str().unwrap())
                    }
                }
            },
            MountTmpfs(dst) => {
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }

                let flags = nixmount::MS_MGC_VAL | nixmount::MS_NOSUID | nixmount::MS_NODEV;
                if let Err(err) = mount(Some("tmpfs"), dst, Some("tmpfs"), flags, Some("mode=0755")) {
                    panic!("Can't mount tmpfs on {}: {}", dst.to_str().unwrap(), err)
                }
            },
            MountMQueue(dst) => {
                let (ref dst, op_dst) = prepare_dst(&dst);
                if let Some(err) = ensure_dir(dst, 0o755) {
                    panic!("Can't mkdir {}: {}", op_dst, err)
                }

                if let Err(err) = mount::<_, _, _, Path>(Some("mqueue"), dst, Some("mqueue"), nixmount::MsFlags::empty(), None) {
                    panic!("Can't mount mqueue on {}: {}", dst.to_str().unwrap(), err)
                }
            },
        }
    }

    // See comment at top about musl
    {
        if let Err(err) = umount2("/proc", nixmount::MntFlags::empty()) {
            panic!("Can't unmount temporary proc :{}", err)
        }
    }
}

fn check_loop_device(path: &Path) {
    // Need https://github.com/nix-rust/nix/pull/508
    type dev_t = u64;
    pub fn major(dev: dev_t) -> u64 {
        ((dev >> 32) & 0xfffff000) |
        ((dev >>  8) & 0x00000fff)
    }
    match path.metadata() {
        Ok(ref metadata) if
            metadata.mode() & libc::S_IFMT == libc::S_IFBLK &&
            major(metadata.rdev()) == 7 => {},
        Ok(_) => panic!("Not a loop device : {}", path.to_str().unwrap()),
        Err(err) => panic!("Can't check source {} loop device: {}", path.to_str().unwrap(), err),
    }
}

/* We need to resolve relative symlinks in the sandbox before we
   chroot so that absolute symlinks are handled correctly. We also
   need to do this after we've switched to the real uid so that
   e.g. paths on fuse mounts work */
#[no_mangle]
pub extern "C" fn resolve_symlinks_in_ops () {
    fn canon(path: &Path) -> PathBuf {
        match path.canonicalize() {
            Ok(path) => path,
            Err(e) => panic!("Can't find path {}: {}", path.to_str().unwrap(), e),
        }
    }
    for op in OPS.lock().unwrap().iter_mut() {
        match *op {
            ROBindMount(ref mut src, _) |
            DevBindMount(ref mut src, _) |
            BindMount(ref mut src, _) |
            MountSquash(ref mut src, _) => {
                *src = canon(src)
            },
            MountSquashOverlay(ref mut src, _, ref mut overlaydir) => {
                *src = canon(src);
                *overlaydir = canon(overlaydir)
            },
            _ => (),
        }
    }
}

#[no_mangle]
pub extern "C" fn usage(ecode: c_int, out: c_int) -> ! {
    usage_and_exit(ecode, out)
}
#[no_mangle]
pub extern "C" fn usage_and_exit(ecode: c_int, out: c_int) -> ! {
    let fd: RawFd = out;
    let mut file = unsafe { File::from_raw_fd(fd) };
    let argv0: String = std::env::args().next().unwrap();

    write!(file, "usage: {} [OPTIONS...] COMMAND [ARGS...]\n", argv0).unwrap();
    write!(file, "
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
"
    ).unwrap();
    process::exit(ecode)
}

#[no_mangle]
pub unsafe extern "C" fn parse_args(argcp: *mut c_int, argvp: *mut *mut *mut c_char) {
    let mut argc = *argcp;
    let mut argv = *argvp;
    /* I can't imagine a case where someone wants more than this.
     * If you do...you should be able to pass multiple files
     * via a single tmpfs and linking them there, etc.
     *
     * We're adding this hardening due to precedent from
     * http://googleprojectzero.blogspot.com/2014/08/the-poisoned-nul-byte-2014-edition.html
     *
     * I picked 9000 because the Internet told me to and it was hard to
     * resist.
     */
    const MAX_ARGS: c_int = 9000;

    if argc > MAX_ARGS {
        panic!("Exceeded maximum number of arguments {}", MAX_ARGS);
    }

    while argc > 0 {
        let arg = CStr::from_ptr(*argv);

        match arg.to_bytes() {
            b"--help" => usage(libc::EXIT_SUCCESS, libc::STDOUT_FILENO),
            b"--version" => {
                println!("{}", PACKAGE_STRING);
                process::exit(0)
            },
            b"--chdir" => {
                if argc < 2 {
                    panic!("--chdir takes one argument")
                }

                opt_chdir_path = *argv.offset(1);
                argv = argv.offset(1);
                argc -= 1
            },
            b"--remount-ro" => {
                if argc < 2 {
                    panic!("--remount-ro takes one argument")
                }

                setup_op_new(RemountRONoRecursive(ptr_to_path(*argv.offset(1))));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--bind" => {
                if argc < 3 {
                    panic!("--bind takes two arguments")
                }

                setup_op_new(BindMount(ptr_to_path(*argv.offset(1)), ptr_to_path(*argv.offset(2))));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--ro-bind" => {
                if argc < 3 {
                    panic!("--ro-bind takes two arguments")
                }

                setup_op_new(ROBindMount(ptr_to_path(*argv.offset(1)), ptr_to_path(*argv.offset(2))));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--dev-bind" => {
                if argc < 3 {
                    panic!("--dev-bind takes two arguments")
                }

                setup_op_new(DevBindMount(ptr_to_path(*argv.offset(1)), ptr_to_path(*argv.offset(2))));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--squash" => {
                if argc < 3 {
                    panic!("--squash takes two arguments")
                }

                setup_op_new(MountSquash(ptr_to_path(*argv.offset(1)), ptr_to_path(*argv.offset(2))));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--squash-overlay" => {
                if argc < 4 {
                    panic!("--squash-overlay takes three arguments")
                }

                setup_op_new(MountSquashOverlay(ptr_to_path(*argv.offset(1)), ptr_to_path(*argv.offset(2)), ptr_to_path(*argv.offset(3))));

                argv = argv.offset(3);
                argc -= 3
            },
            b"--proc" => {
                if argc < 2 {
                    panic!("--proc takes one argument")
                }

                setup_op_new(MountProc(ptr_to_path(*argv.offset(1))));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--dev" => {
                if argc < 2 {
                    panic!("--dev takes one argument")
                }

                setup_op_new(MountDev(ptr_to_path(*argv.offset(1))));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--tmpfs" => {
                if argc < 2 {
                    panic!("--tmpfs takes one argument")
                }

                setup_op_new(MountTmpfs(ptr_to_path(*argv.offset(1))));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--mqueue" => {
                if argc < 2 {
                    panic!("--mqueue takes one argument")
                }

                setup_op_new(MountMQueue(ptr_to_path(*argv.offset(1))));

                argv = argv.offset(1);
                argc -= 1
            },
            &[b'-', ..] => panic!("Unknown option {:?}", arg),
            _ => break,
        }

        argv = argv.offset(1);
        argc -= 1;
    }

    *argcp = argc;
    *argvp = argv;
}

#[link(name = "machroot", kind = "static")]
extern "C" {
    fn machroot(argc: c_int, argv: *mut *mut c_char);
    fn bind_mount(proc_fd: c_int, src: *const c_char, dst: *const c_char, options: BindOption) -> c_int;
}

fn main() {
    let args: Vec<CString> = std::env::args()
        .map(|arg| CString::new(arg).unwrap()).collect();
    let mut c_args: Vec<*mut c_char> = args.iter()
        .map(|arg| arg.as_ptr() as *mut _).collect();
    c_args.push(ptr::null_mut());
    unsafe {
        machroot((c_args.len()-1) as c_int, c_args.as_ptr() as *mut _);
    }
}
