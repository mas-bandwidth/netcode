extern crate gcc;

pub fn main() {
    gcc::Config::new()
        .file("netcode/netcode.c")
        .include("netcode")
        .include("netcode/windows")
        .define("NETCODE_ENABLE_TESTS", Some("0"))
        .define("NDEBUG", Some("0"))
        .compile("libnetcode.a");

    println!("cargo:rustc-link-search=native=netcode/windows");
    println!("cargo:rustc-link-lib=static=sodium-release");
}