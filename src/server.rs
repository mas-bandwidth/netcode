//! This module holds a netcode.io server implemenation and all of its related functions.

use std::net::{UdpSocket, ToSocketAddrs, SocketAddr};
use std::io;

use common::*;

/// Errors from creating a server.
#[derive(Debug)]
pub enum CreateError {
    /// Address is already in use.
    AddrInUse,
    /// Address is not available(and probably already bound).
    AddrNotAvailable,
    /// Private key is not the correct size (`NETCODE_KEY_BYTES` = 4096).
    InvalidKeySize,
    /// Generic(other) io error occured.
    GenericIo(io::Error)
}

/// Errors from updating server.
#[derive(Debug)]
pub enum UpdateError {
    /// Packet buffer was too small to recieve the largest packet(`NETCODE_MAX_PACKET_SIZE` = 1200)
    PacketBufferTooSmall,
    /// Generic io error.
    SocketError(io::Error)
}

/// Enum that describes and event from the server.
pub enum UpdateEvent {
    /// A client has connected, contains a reference to the client that was just created.
    ClientConnect(Client),
    /// A client has disconnected, contains the clien that was just disconnected.
    ClientDisconnect(Client),
    /// Called when client tries to connect but all slots are full.
    ClientSlotFull,
    /// We recieved a packet, out_packet will be filled with data based on `usize`, contains a reference to the client that reieved the packet.
    Packet(Client, usize)
}

/// Current state of the client connection.
#[derive(Clone)]
enum ClientState {
    /// We've recieved the initial packet but response is outstanding yet.
    PendingResponse,
    /// Handshake is complete and client is connected.
    Connected,
    /// Client timed out from heartbeat packets.
    TimedOut,
    /// Client has cleanly disconnected.
    Disconnected
}

/// Handle to client connection.
#[derive(Clone)]
pub struct Client {
    state: ClientState,
    addr: SocketAddr
}

/// UDP based server connection.
pub type Server = ServerImpl<UdpSocket>;

pub struct ServerImpl<I> where I: Socket<I> {
    socket: I,
    private_key: [u8; NETCODE_KEY_BYTES],
    //@todo: We could probably use a free list or something smarter here if
    //we find that performance is an issue.
    clients: Vec<Option<Client>>,
    time: f64
}

impl<I> ServerImpl<I> where I: Socket<I> {
    /// Constructs a new Server bound to `local_addr` with `max_clients` and supplied `private_key` for authentication.
    pub fn new<A>(local_addr: A, max_clients: usize, private_key: &[u8]) -> Result<ServerImpl<I>, CreateError> where A: ToSocketAddrs {
        if private_key.len() != NETCODE_KEY_BYTES {
            return Err(CreateError::InvalidKeySize)
        }

        match I::bind(local_addr) {
            Ok(s) => {
                let mut key_copy: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];
                key_copy.copy_from_slice(private_key);

                let mut clients = Vec::with_capacity(max_clients);
                clients.resize(max_clients, None);

                Ok(ServerImpl {
                    socket: s,
                    private_key: key_copy,
                    clients: clients,
                    time: 0.0
                })
            },
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::AddrInUse => Err(CreateError::AddrInUse),
                    io::ErrorKind::AddrNotAvailable => Err(CreateError::AddrNotAvailable),
                    _ => Err(CreateError::GenericIo(e))
                }
            }
        }
    }

    /// Updates time elapsed since last server iteration.
    pub fn update(&mut self, elapsed: f64) -> ServerUpdateIter<I> {
        self.time += elapsed;

        ServerUpdateIter {
            server: self,
            idx: 0
        }
    }
    
    /// Checks for incoming packets, client connection and disconnections. Returns `Ok(None)` when no more events
    /// are pending.
    pub fn next_event(&mut self, out_packet: &mut [u8]) -> Result<Option<UpdateEvent>, UpdateError> {
        if out_packet.len() < NETCODE_MAX_PACKET_SIZE {
            return Err(UpdateError::PacketBufferTooSmall)
        }

        match self.socket.recv_from(out_packet) {
            Ok((n, addr)) => {
                match self.find_client(addr) {
                    Some(idx) => {
                        Ok(Some(UpdateEvent::Packet(self.clients[idx].clone().unwrap(), n)))
                    },
                    None => {
                        match self.clients.iter().position(|v| v.is_none()) {
                            Some(idx) => {
                                self.clients[idx] = Some(Client {
                                    state: ClientState::PendingResponse,
                                    addr: addr
                                });

                                Ok(Some(UpdateEvent::ClientConnect(self.clients[idx].clone().unwrap())))
                            },
                            None => {
                                info!("Unable to find free client slot, max clients connected");
                                return Ok(Some(UpdateEvent::ClientSlotFull))
                            }
                        }
                    }
                }
            },
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    _ => Err(UpdateError::SocketError(e))
                }
            }
        }
    }

    fn find_client(&mut self, addr: SocketAddr) -> Option<usize> {
        self.clients.iter().cloned().filter_map(|c| c).position(|c| c.addr == addr)
    }
}

pub struct ServerUpdateIter<'a,I> where I: Socket<I> + 'static {
    server: &'a mut ServerImpl<I>,
    idx: usize
}

#[test]
fn create_server() {
    ServerImpl::<MockedSocket>::new("127.0.0.1:8080", 256, &[0; NETCODE_KEY_BYTES]).expect("Failed to create server");
}