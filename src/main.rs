extern crate libc;

use std::ffi::CString;
use std::ptr;

use libc::{c_char, c_int};

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
