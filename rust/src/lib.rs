extern crate libsodium_sys;
extern crate byteorder;
#[macro_use]
extern crate log;
extern crate net2;

#[cfg(test)]
extern crate env_logger;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

pub mod wrapper;

mod common;
mod crypto;
mod server;
mod token;
mod packet;

pub use token::{ConnectToken, PrivateData, HostIterator};
pub use common::{NETCODE_MAX_PACKET_SIZE, NETCODE_MAX_PAYLOAD_SIZE, NETCODE_USER_DATA_BYTES};
pub use server::{UdpServer, Server, ServerEvent, UpdateError, SendError};
pub use crypto::{generate_key};
