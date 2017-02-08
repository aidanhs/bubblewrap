#![feature(const_fn)]
#![feature(field_init_shorthand)]
#![feature(slice_patterns)]

#[macro_use]
extern crate lazy_static;
extern crate libc;

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use std::ptr;
use std::sync::Mutex;

use libc::{c_char, c_int};

use SetupOpType::*;

#[repr(u32)]
pub enum SetupOpType {
    SETUP_BIND_MOUNT = 0,
    SETUP_RO_BIND_MOUNT,
    SETUP_DEV_BIND_MOUNT,
    SETUP_MOUNT_PROC,
    SETUP_MOUNT_DEV,
    SETUP_MOUNT_TMPFS,
    SETUP_MOUNT_MQUEUE,
    SETUP_REMOUNT_RO_NO_RECURSIVE,
}

#[repr(C)]
pub struct SetupOp {
    ty: SetupOpType,
    src: *const c_char,
    dest: *const c_char,
}

// TODO: not really
unsafe impl Send for SetupOp {}

const PACKAGE_STRING: &'static str = "machroot 0.1.0";

#[no_mangle]
pub static mut opsvec: *const SetupOp = ptr::null();
#[no_mangle]
pub static mut opsveclen: libc::uint64_t = 0;

#[no_mangle]
pub static mut opt_chdir_path: *const c_char = ptr::null();

lazy_static! {
    static ref OPS: Mutex<Vec<SetupOp>> = Mutex::new(vec![]);
}

#[no_mangle]
pub extern "C" fn setup_op_new (ty: SetupOpType, src: *const c_char, dest: *const c_char) {
    let mut ops = OPS.lock().unwrap();
    ops.push(SetupOp { ty, src, dest });
    unsafe {
        opsvec = ops.as_ptr();
        opsveclen = ops.len() as u64;
    }
}

/* We need to resolve relative symlinks in the sandbox before we
   chroot so that absolute symlinks are handled correctly. We also
   need to do this after we've switched to the real uid so that
   e.g. paths on fuse mounts work */
#[no_mangle]
pub extern "C" fn resolve_symlinks_in_ops () {
    for op in OPS.lock().unwrap().iter_mut() {
        match op.ty {
            SETUP_RO_BIND_MOUNT |
            SETUP_DEV_BIND_MOUNT |
            SETUP_BIND_MOUNT => unsafe {
                let old_src = op.src;
                // TODO: leaks
                op.src = libc::realpath(old_src, ptr::null_mut());
                if op.src == ptr::null_mut() {
                    panic!("Can't find src path {:?}", CStr::from_ptr(old_src))
                }
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
    --help                       Print this help
    --version                    Print version
    --chdir DIR                  Change directory to DIR
    --bind SRC DEST              Bind mount the host path SRC on DEST
    --dev-bind SRC DEST          Bind mount the host path SRC on DEST, allowing device access
    --ro-bind SRC DEST           Bind mount the host path SRC readonly on DEST
    --remount-ro DEST            Remount DEST as readonly, it doesn't recursively remount
    --proc DEST                  Mount procfs on DEST
    --dev DEST                   Mount new dev on DEST
    --tmpfs DEST                 Mount new tmpfs on DEST
    --mqueue DEST                Mount new mqueue on DEST
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

                setup_op_new(SETUP_REMOUNT_RO_NO_RECURSIVE, ptr::null(), *argv.offset(1));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--bind" => {
                if argc < 3 {
                    panic!("--bind takes two arguments")
                }

                setup_op_new(SETUP_BIND_MOUNT, *argv.offset(1), *argv.offset(2));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--ro-bind" => {
                if argc < 3 {
                    panic!("--ro-bind takes two arguments")
                }

                setup_op_new(SETUP_RO_BIND_MOUNT, *argv.offset(1), *argv.offset(2));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--dev-bind" => {
                if argc < 3 {
                    panic!("--dev-bind takes two arguments")
                }

                setup_op_new(SETUP_DEV_BIND_MOUNT, *argv.offset(1), *argv.offset(2));

                argv = argv.offset(2);
                argc -= 2
            },
            b"--proc" => {
                if argc < 2 {
                    panic!("--proc takes one argument")
                }

                setup_op_new(SETUP_MOUNT_PROC, ptr::null(), *argv.offset(1));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--dev" => {
                if argc < 2 {
                    panic!("--dev takes one argument")
                }

                setup_op_new(SETUP_MOUNT_DEV, ptr::null(), *argv.offset(1));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--tmpfs" => {
                if argc < 2 {
                    panic!("--tmpfs takes one argument")
                }

                setup_op_new(SETUP_MOUNT_TMPFS, ptr::null(), *argv.offset(1));

                argv = argv.offset(1);
                argc -= 1
            },
            b"--mqueue" => {
                if argc < 2 {
                    panic!("--mqueue takes one argument")
                }

                setup_op_new(SETUP_MOUNT_MQUEUE, ptr::null(), *argv.offset(1));

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
