//! Rust implementation of netcode.io protocol.
//!
//! This crate contains [Server](struct.Server.html), Client(TBD) and [ConnectToken](struct.ConnectToken.html) used to establish a netcode.io session.
//! 
//! # Connect Token
//! Each netcode.io session starts with a `ConnectToken`. This token is handed out by a HTTPS webserver, authentication server or other *private* avenue
//! to allow a client to establish a connection with a netcode.io based server. Rather than specifying an address the list of hosts are contained within
//! the token. Note that private keys are included in the clear so HTTPS or other secure measures for delivering the token to the client are required.
//!
//! # Server
//! The netcode.io server is created within the [UDPServer](type.UdpServer.html)::new(...) call. It accepts a local address, number of clients and private key
//! used to sign the `ConnectToken`s send to the connecting clients.
//!
//! # Example
//! ```
//! use netcode::UdpServer;
//! use netcode::ServerEvent;
//!
//! const PROTOCOL_ID: u64 = 0xFFEE;
//! const MAX_CLIENTS: usize = 32;
//! let private_key = netcode::generate_key();
//! let mut server = UdpServer::new("127.0.0.1:0", MAX_CLIENTS, PROTOCOL_ID, &private_key).unwrap();
//!
//! //loop {
//!     server.update(1.0 / 10.0);
//!     let mut packet_data = [0; netcode::NETCODE_MAX_PAYLOAD_SIZE];
//!     match server.next_event(&mut packet_data) {
//!         Ok(Some(e)) => {
//!             match e {
//!                 ServerEvent::ClientConnect(_id) => {},
//!                 ServerEvent::ClientDisconnect(_id) => {},
//!                 ServerEvent::Packet(_id,_size) => {},
//!                 _ => ()
//!             }
//!         },
//!         Ok(None) => (),
//!         Err(err) => Err(err).unwrap()
//!     }
//! //}
//! ```

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

#[cfg(test)]
pub mod capi;

mod common;
pub mod error;
mod crypto;
mod server;
mod client;
mod channel;
mod replay;
mod token;
mod packet;
mod socket;

pub use token::{ConnectToken};
pub use common::{NETCODE_MAX_PACKET_SIZE, NETCODE_MAX_PAYLOAD_SIZE, NETCODE_USER_DATA_BYTES};
pub use server::{UdpServer, Server, ServerEvent};
pub use crypto::{generate_key};
