fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if matches!(std::env::var("CARGO_CFG_TARGET_OS").as_deref(), Ok("linux")) {
        println!("cargo::rustc-cdylib-link-arg=-Wl,-soname,libpurify_construction_parent.so");
    }
}
