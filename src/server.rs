use std::net::{UdpSocket, ToSocketAddrs, SocketAddr};
use std::io;

use common::*;

#[derive(Debug)]
pub enum CreateError {
    AddrInUse,
    AddrNotAvailable,
    InvalidKeySize,
    GenericIo(io::Error)
}

#[derive(Debug)]
pub enum UpdateError {
    PacketBufferTooSmall,
    SocketError(io::Error)
}

pub enum UpdateEvent<'a> {
    ClientConnect(),
    ClientDisconnect(),
    Packet(&'a Client, usize)
}

#[derive(Clone)]
enum ClientState {
}

#[derive(Clone)]
pub struct Client {
    state: ClientState,
    addr: SocketAddr
}

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

    pub fn update(&mut self, elapsed: f64, out_packet: &mut [u8]) -> Result<Option<UpdateEvent>, UpdateError> {
        if out_packet.len() < NETCODE_MAX_PACKET_SIZE {
            return Err(UpdateError::PacketBufferTooSmall)
        }

        self.time += elapsed;

        match self.socket.recv_from(out_packet) {
            Ok((n, addr)) => {
                match self.find_client(addr) {
                    Some(client) => {
                        Ok(Some(UpdateEvent::Packet(client, n)))
                    },
                    None => {
                        Ok(Some(UpdateEvent::ClientConnect()))
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

    fn find_client(&mut self, addr: SocketAddr) -> Option<&mut Client> {
        for client in &mut self.clients {
            match client {
                &mut Some(ref mut client) => {
                    if client.addr == addr {
                        return Some(client)
                    }
                },
                &mut None => ()
            }
        }

        None
    }
}

#[test]
fn create_server() {
    ServerImpl::<MockedSocket>::new("127.0.0.1:8080", 256, &[0; NETCODE_KEY_BYTES]).expect("Failed to create server");
}