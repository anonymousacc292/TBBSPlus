extern crate dunce;
use std::{env, path::PathBuf};

fn main() {
	let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = dunce::canonicalize(root.join("src/lib")).unwrap();
    println!("cargo:rustc-link-search=native={}", env::join_paths(&[library_dir]).unwrap().to_str().unwrap());
    println!("cargo:rustc-link-lib=static=rust_genprime");
    //println!("cargo:rustc-link-search=native=/usr/lib/gcc/x86_64-linux-gnu/7/");
    //println!("cargo:rustc-flags=-lstdc++");
    //println!("cargo:rustc-link-lib=static=stdc++");
    //println!("cargo:rustc-link-lib=dylib=stdc++");
    //println!("cargo:rustc-link-lib=static=stdc++");
    //println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
    //println!("cargo:rustc-link-lib=static=gmp");
    //println!("cargo:rustc-link-lib=static=stdc++");
    //println!("cargo:rustc-flags=-Clinker-plugin-lto -L. -Copt-level=2 -Clinker=clang -Clink-arg=-fuse-ld=lld");
}
