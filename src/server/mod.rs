//! This module holds a netcode.io server implemenation and all of its related functions.

use std::net::{ToSocketAddrs, SocketAddr};
use std::io;
use std::time;

use mio;

use common::*;
use packet;

mod connection;
use server::connection::*;
mod socket;
use server::socket::*;

/// Errors from creating a server.
#[derive(Debug)]
pub enum CreateError {
    /// Address is already in use.
    AddrInUse,
    /// Address is not available(and probably already bound).
    AddrNotAvailable,
    /// Generic(other) io error occured.
    GenericIo(io::Error)
}

impl From<io::Error> for CreateError {
    fn from(err: io::Error) -> CreateError {
        CreateError::GenericIo(err)
    }
}

/// Errors from updating server.
#[derive(Debug)]
pub enum UpdateError {
    /// Packet buffer was too small to recieve the largest packet(`NETCODE_MAX_PACKET_SIZE` = 1200)
    PacketBufferTooSmall,
    /// Generic io error.
    SocketError(io::Error)
}

impl From<io::Error> for UpdateError {
    fn from(err: io::Error) -> UpdateError {
        UpdateError::SocketError(err)
    }
}

/// Enum that describes and event from the server.
pub enum ServerEvent {
    /// A client has connected, contains a reference to the client that was just created.
    ClientConnect(Connection),
    /// A client has disconnected, contains the clien that was just disconnected.
    ClientDisconnect(Connection),
    /// Called when client tries to connect but all slots are full.
    ClientSlotFull,
    /// We recieved a packet, out_packet will be filled with data based on `usize`, contains a reference to the client that reieved the packet.
    Packet(Connection, usize)
}

pub type UdpServer = Server<mio::udp::UdpSocket>;

const SERVER_TOKEN: mio::Token = mio::Token(0);

pub struct Server<I> {
    listen_socket: I,
    listen_addr: SocketAddr,
    event_queue: mio::Poll,
    event_list: mio::Events,
    private_key: [u8; NETCODE_KEY_BYTES],
    //@todo: We could probably use a free list or something smarter here if
    //we find that performance is an issue.
    clients: Vec<Option<(Connection, I)>>,
    time: f64,

    client_event_idx: usize,
    io_event_idx: usize
}

impl<I> Server<I> where I: SocketProvider<I> + mio::Evented + Clone {
    /// Constructs a new Server bound to `local_addr` with `max_clients` and supplied `private_key` for authentication.
    pub fn new<A>(local_addr: A, max_clients: usize, private_key: &[u8; NETCODE_KEY_BYTES]) -> Result<Server<I>, CreateError> where A: ToSocketAddrs {
        let bind_addr = local_addr.to_socket_addrs().unwrap().next().unwrap();
        match I::bind(&bind_addr) {
            Ok(s) => {
                let mut key_copy: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];
                key_copy.copy_from_slice(private_key);

                let mut clients = Vec::with_capacity(max_clients);
                clients.resize(max_clients, None);

                let poll = mio::Poll::new()?;
                poll.register(&s, SERVER_TOKEN, mio::Ready::readable(), mio::PollOpt::edge())?;

                Ok(Server {
                    listen_socket: s,
                    listen_addr: bind_addr,
                    event_queue: poll,
                    event_list: mio::Events::with_capacity(1024),
                    private_key: key_copy,
                    clients: clients,
                    time: 0.0,
                    client_event_idx: 0,
                    io_event_idx: 0
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
    pub fn update(&mut self, elapsed: f64, block_duration: time::Duration) -> Result<(), io::Error> {
        self.time += elapsed;
        self.event_queue.poll(&mut self.event_list, Some(block_duration))?;

        Ok(())
    }
    
    /// Checks for incoming packets, client connection and disconnections. Returns `None` when no more events
    /// are pending.
    pub fn next_event(&mut self, out_packet: &mut [u8]) -> Result<Option<ServerEvent>, UpdateError> {
        if out_packet.len() < NETCODE_MAX_PACKET_SIZE {
            return Err(UpdateError::PacketBufferTooSmall)
        }

        loop {
            if self.io_event_idx >= self.event_list.len() {
                break;
            }

            let result = self.event_list.get(self.io_event_idx)
                .map(|io_event| self.handle_io(io_event, out_packet));

            self.io_event_idx += 1;

            if result.is_some() {
                return result.unwrap()
            }
        }

        loop {
            if self.client_event_idx >= self.clients.len() {
                break;
            }

            let (remove, result) = match self.clients[self.client_event_idx] {
                Some(ref mut c) => Server::handle_client(self.time, c),
                None => (false, None)
            };

            if remove {
                self.clients[self.client_event_idx] = None;
            }

            self.client_event_idx += 1;

            if result.is_some() {
                return result.map_or(Ok(None), |r| r.map(|i| Some(i)))
            }
        }

        Ok(None)
    }

    fn handle_io(&mut self, io_event: mio::Event, out_packet: &mut [u8]) -> Result<Option<ServerEvent>, UpdateError> {
        match io_event.token() {
            mio::Token(0) => {
                trace!("New data on listening socket");
                //Accept new client
                self.handle_client_connect(out_packet)
            },
            mio::Token(n) => {
                let client_idx = n-1;

                if let Some(&mut (ref mut client, ref mut socket)) = self.clients[client_idx].as_mut() {
                    let time = self.time;
                    socket.recv(out_packet)
                        .map_err(|e| e.into())
                        .and_then(|read| {
                            Self::handle_packet(time, (client, socket), out_packet, read.unwrap_or(0))
                        })
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn handle_client_connect(&mut self, out_packet: &mut [u8]) -> Result<Option<ServerEvent>, UpdateError> {
        //Find open index
        match self.clients.iter().position(|v| v.is_none()) {
            Some(idx) => {
                match self.listen_socket.recv_from(out_packet)? {
                    Some((size, addr)) => {
                        info!("Accepting connection from {}", &addr);

                        use std::str::FromStr;
                        //@todo: pick ipv6 if we are using ipv6
                        let bind_addr = format!("0.0.0.0:{}", self.listen_addr.port());
                        let mut socket = I::bind(&SocketAddr::from_str(bind_addr.as_str()).unwrap())?;
                        socket.connect(addr)?;

                        let conn = Connection {
                            addr: addr,
                            state: ConnectionState::PendingResponse(self.time)
                        };

                        self.validate_client_token(&out_packet[..size])?;

                        self.clients[idx] = Some((conn.clone(), socket));

                        trace!("Accepted connection");

                        Ok(Some(ServerEvent::ClientConnect(conn.clone())))
                    },
                    None => Ok(None)
                }
            },
            None => {
                trace!("Tried to accept new client but max clients connected: {}", self.clients.len());
                Ok(Some(ServerEvent::ClientSlotFull))
            }
        }
    }

    fn validate_client_token(&mut self, packet: &[u8]) -> Result<(), UpdateError> {
        //let packet = packet::decode()
        Ok(())
    }

    fn handle_client(time: f64, client: &mut (Connection, I)) -> (bool, Option<Result<ServerEvent, UpdateError>>) {
        match client.0.state {
            ConnectionState::PendingResponse(n) | ConnectionState::Idle(n) => {
                if n + NETCODE_TIMEOUT_SECONDS as f64 >= time {
                    client.0.state = ConnectionState::TimedOut;
                    (false, Some(Ok(ServerEvent::ClientConnect(client.0.clone()))))
                } else {
                    (false, None)
                }
            },
            ConnectionState::Connected => { 
                client.0.state = ConnectionState::Idle(time); 
                (false, None)
            },
            ConnectionState::TimedOut 
                | ConnectionState::Disconnected => (true, None),
        }
    }

    fn handle_packet(time: f64, (client, socket): (&mut Connection, &mut I), packet: &mut [u8], read: usize) -> Result<Option<ServerEvent>, UpdateError> {
        if read == 0 {
            return Ok(None)
        }

        //Update client state with any recieved packet
        client.state = match client.state.clone() {
            ConnectionState::Connected => ConnectionState::Idle(time),
            ConnectionState::Idle(_) => ConnectionState::Idle(time),
            ConnectionState::PendingResponse(_) => ConnectionState::Connected,
            s => s
        };

        Ok(Some(ServerEvent::Packet(client.clone(), read)))
    }

    fn find_client(&mut self, addr: SocketAddr) -> Option<usize> {
        self.clients.iter().cloned().filter_map(|c| c).position(|(c,_)| c.addr == addr)
    }
}