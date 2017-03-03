extern crate gcc;

pub fn main() {
    gcc::Config::new()
        .file("netcode/c/netcode.c")
        .include("netcode/c")
        .include("netcode/c/windows")
        .define("NETCODE_ENABLE_TESTS", Some("0"))
        .define("NDEBUG", Some("0"))
        .compile("libnetcode.a");

    println!("cargo:rustc-link-search=native=netcode/c/windows");
    println!("cargo:rustc-link-lib=static=sodium-release");
}