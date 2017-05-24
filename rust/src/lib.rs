//! Rust implementation of netcode.io protocol.
//!
//! This crate contains [Server](struct.Server.html), [Client](struct.Client.html) and [ConnectToken](struct.ConnectToken.html) used to establish a netcode.io session.
//!
//! # Connect Token
//! Each netcode.io session starts with a [ConnectToken](struct.ConnectToken.html). This token is handed out by a HTTPS webserver, authentication server or other *private* avenue
//! to allow a client to establish a connection with a netcode.io based server. Rather than specifying an address the list of hosts are contained within
//! the token. Note that private keys are included in the clear so HTTPS or other secure measures for delivering the token to the client are required.
//!
//! # Server
//! The netcode.io server is created with the [UDPServer](type.UdpServer.html)::new(...) call. It accepts a local address, number of clients and private key
//! used to sign the `ConnectToken`s send to the connecting clients.
//!
//! # Client
//! The netcode.io client is created with the [UDPClient](type.UdpClient.html)::new(...) call. It accepts a connection token that has been handed out from a
//! webserver or equivalent secure connection.
//!
//! # Server Example
//! ```rust
//! use netcode::{UdpServer, ServerEvent};
//!
//! fn run_server() {
//!     const PROTOCOL_ID: u64 = 0xFFEE;
//!     const MAX_CLIENTS: usize = 32;
//!     let mut server = UdpServer::new("127.0.0.1:0",
//!                                     MAX_CLIENTS,
//!                                     PROTOCOL_ID,
//!                                     &netcode::generate_key()).unwrap();
//!
//!     loop {
//!         server.update(1.0 / 10.0);
//!         let mut packet_data = [0; netcode::NETCODE_MAX_PAYLOAD_SIZE];
//!         match server.next_event(&mut packet_data) {
//!             Ok(Some(e)) => {
//!                 match e {
//!                     ServerEvent::ClientConnect(_id) => {},
//!                     ServerEvent::ClientDisconnect(_id) => {},
//!                     ServerEvent::Packet(_id,_size) => {
//!                         //Packet from `id` of `size` length stored in `packet_data`
//!                     },
//!                     _ => {}
//!                 }
//!             },
//!             Ok(None) => {},
//!             Err(err) => Err(err).unwrap()
//!         }
//!
//!         //Tick world/gamestate/etc.
//!         //Sleep till next frame.
//!     }
//! }
//! ```
//!
//! # Client Example
//! ```rust
//! use netcode::{UdpClient, ClientEvent, ClientState, ConnectToken};
//! use std::io;
//!
//! fn run_client() {
//!     let token_data = [0; 1024]; //Note that this should come from your webserver
//!                                 //or directly from the server you're connecting to.
//!                                 //It must be sent over a secure channel because
//!                                 //it contains private keys in the clear.
//!     let token = ConnectToken::read(&mut io::Cursor::new(&token_data[..])).unwrap();
//!     let mut client = UdpClient::new(&token).unwrap();
//!     loop {
//!         client.update(1.0 / 10.0);
//!         let mut packet_data = [0; netcode::NETCODE_MAX_PAYLOAD_SIZE];
//!         match client.next_event(&mut packet_data) {
//!             Ok(Some(e)) => {
//!                 match e {
//!                     ClientEvent::NewState(state) => match state {
//!                         ClientState::Connected => {},
//!                         ClientState::Disconnected => {},
//!                         _ => {}
//!                     },
//!                     ClientEvent::Packet(_size) => {
//!                         //Packet of `size` length stored in `packet_data`
//!                     },
//!                     _ => {}
//!                 }
//!             },
//!             Ok(None) => {},
//!             Err(err) => Err(err).unwrap()
//!         }
//!
//!         //Sleep till next frame.
//!     }
//! }
//! ```
//!
//! # Token Example
//! ```
//! use netcode::{self, ConnectToken};
//! use std::io;
//!
//! const EXPIRE_SECONDS: usize = 30;
//! const PROTOCOL_ID: u64 = 0xFFEE;
//!
//! # fn get_client_id() -> u64 { 0 }
//! # fn get_next_sequence() -> u64 { 0 }
//! let private_key = netcode::generate_key(); //Note: You probably want to
//!                                            //store this some where safe.
//! let client_id = get_client_id(); //Unique u64 client id.
//! let sequence = get_next_sequence(); //sequence passed to generate() must
//!                                     //be a monotically increasing u64
//!                                     //to prevent replay attacks.
//! let user_data = None;   //Any custom user data, can be up to 256 bytes.
//!                         //Will be encrypted and returned to sever on connect.
//!
//! let token = ConnectToken::generate_with_string(["127.0.0.1:5000"].iter().cloned(),
//!                                                &private_key,
//!                                                EXPIRE_SECONDS,
//!                                                sequence,
//!                                                PROTOCOL_ID,
//!                                                client_id,
//!                                                user_data).unwrap();
//! let mut token_data = vec!();
//! token.write(&mut token_data).unwrap();
//! ```
//! ```rust
//! # use netcode::{UdpServer};
//! //Alteratively if you already have a server you can generate a token like below:
//! const PROTOCOL_ID: u64 = 0xFFEE;
//! const MAX_CLIENTS: usize = 32;
//! let mut server = UdpServer::new("127.0.0.1:0",
//!                                 MAX_CLIENTS,
//!                                 PROTOCOL_ID,
//!                                 &netcode::generate_key()).unwrap();
//!
//! const EXPIRE_SECONDS: usize = 30;
//! # fn get_client_id() -> u64 { 0 }
//! let client_id = get_client_id(); //Unique u64 client id.
//!
//! let token = server.generate_token(EXPIRE_SECONDS, client_id, None).unwrap();
//! ```

extern crate libsodium_sys;
extern crate byteorder;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate env_logger;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(test)]
pub mod capi;

mod common;
mod error;
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
pub use client::{UdpClient, Client, ClientEvent, State as ClientState};
pub use crypto::{generate_key};
pub use error::*;
