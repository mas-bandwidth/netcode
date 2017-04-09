extern crate gcc;
extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::time::{Duration};

pub fn main() {
    gcc::Config::new()
        .file("../c/netcode.c")
        .include("../c")
        .include("../c/windows")
        .define("NETCODE_ENABLE_TESTS", Some("0"))
        .define("NDEBUG", Some("0"))
        .compile("libnetcode.a");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let pub_path = out_path.join("pub_bindings.rs");
    let private_path = out_path.join("private_bindings.rs");

    //Do some basic dependecy management
    let targets = vec!(&pub_path, &private_path);
    let source = vec!("build.rs", "../c/netcode.c", "../c/netcode.h").iter()
        .map(|v| PathBuf::from(v))
        .collect::<Vec<_>>();

    let newest_source = source.iter()
        .map(|v| {
            File::open(v)
                .and_then(|f| f.metadata())
                .and_then(|m| m.modified())
                .expect(format!("Source file {:?} not found", v).as_str())
        })
        .max()
        .unwrap();

    let oldest_target = targets.iter()
        .filter_map(|v| {
            File::open(v)
                .and_then(|f| f.metadata())
                .and_then(|m| m.modified())
                .ok()
        })
        .min()
        .unwrap_or(newest_source - Duration::from_secs(1));

    if newest_source > oldest_target {
        //Export symbols for netcode
        let pub_bindings = bindgen::Builder::default()
            .no_unstable_rust()
            .header("../c/netcode.h")
            .generate()
            .expect("Unable to generate bindings");

        pub_bindings.write_to_file(&pub_path)
            .expect("Couldn't write bindings!");

        let include = env::var("INCLUDE").unwrap_or("".to_string());
        let sodium_include = env::var("SODIUM_LIB_DIR")
                                 .unwrap_or("../c/windows".to_string());

        let private_bindings = bindgen::Builder::default()
            .no_unstable_rust()
            .header("../c/netcode.c")
            .clang_arg("-I../c")
            .clang_arg(format!("-I{}", sodium_include))
            .clang_arg(format!("-I{}", include))
            .whitelisted_function("netcode_log_level")
            .whitelisted_function("netcode_write_packet")
            .whitelisted_function("netcode_read_packet")
            .whitelisted_function("netcode_read_connect_token")
            .whitelisted_function("netcode_decrypt_challenge_token")
            .whitelisted_function("netcode_read_challenge_token")
            .whitelisted_function("netcode_replay_protection_reset")
            .whitelisted_function("free")
            .whitelisted_function("netcode_init")
            .whitelisted_function("netcode_client_create_internal")
            .whitelisted_function("netcode_client_connect")
            .whitelisted_function("netcode_client_update")
            .whitelisted_function("netcode_client_state")
            .whitelisted_function("netcode_client_receive_packet")
            .whitelisted_function("netcode_client_free_packet")
            .whitelisted_function("netcode_client_destroy")
            .whitelisted_function("netcode_client_receive_packet")
            .whitelisted_function("netcode_client_free_packet")
            .whitelisted_function("netcode_term")
            .whitelisted_type("netcode_network_simulator_t")
            .whitelisted_type("netcode_address_t")
            .whitelisted_function("netcode_network_simulator_create")
            .whitelisted_function("netcode_network_simulator_destroy")
            .whitelisted_function("netcode_network_simulator_update")
            .whitelisted_function("netcode_network_simulator_send_packet")
            .whitelisted_function("netcode_network_simulator_receive_packets")
            .whitelisted_function("netcode_parse_address")
            .whitelisted_function("netcode_address_to_string")
            .whitelisted_var("NETCODE_MAX_ADDRESS_STRING_LENGTH")
            .whitelisted_var("NETCODE_CONNECTION_NUM_PACKETS")
            .whitelisted_var("NETCODE_CLIENT_STATE_CONNECTED")
            .whitelisted_var("NETCODE_CLIENT_STATE_DISCONNECTED")
            .whitelisted_var("NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE")
            .whitelisted_var("NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST")
            .whitelisted_var("NETCODE_LOG_LEVEL_DEBUG")
            .whitelisted_var("NETCODE_PACKET_SEND_RATE")
            .generate()
            .expect("Unable to generate bindings");

        private_bindings.write_to_file(&private_path)
            .expect("Couldn't write bindings!");

        //Todo: Pull in constants for timeout/etc into a separate file.
    }
}
