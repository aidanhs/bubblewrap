#![feature(const_fn)]
#![feature(field_init_shorthand)]

#[macro_use]
extern crate lazy_static;
extern crate libc;

use std::ffi::{CStr, CString};
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

unsafe impl Send for SetupOp {}

#[no_mangle]
pub static mut opsvec: *const SetupOp = ptr::null();
#[no_mangle]
pub static mut opsveclen: libc::uint64_t = 0;

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
