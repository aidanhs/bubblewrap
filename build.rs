use std::process::Command;
use std::env;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = out_dir.as_str();

    assert!(Command::new("./script.sh").status().unwrap().success());
    assert!(Command::new("cp").args(&[
        "libmachroot.a", out_dir
    ]).status().unwrap().success());

    println!("cargo:rustc-link-search=native={}", out_dir);
}
