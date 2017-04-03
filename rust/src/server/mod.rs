//! This module holds a netcode.io server implemenation and all of its related functions.

use std::net::{ToSocketAddrs, SocketAddr};
use std::io;
use std::time;

use mio;

use common::*;
use packet;
use token;
use crypto;

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
    /// Generic(other) io error occurred.
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
    SocketError(io::Error),
    /// An error when sending(usually challenge response)
    SendError(SendError),
    /// An internal error occurred
    Internal(InternalError)
}

#[derive(Debug)]
/// Errors internal to netcode.
pub enum InternalError {
    ChallengeEncodeError(packet::ChallengeEncodeError)
}

//Errors from sending packets
#[derive(Debug)]
pub enum SendError {
    /// Client Id used for sending didn't exist.
    InvalidClientId,
    /// Failed to encode the packet for sending.
    PacketEncodeError(packet::PacketError),
    /// Generic io error.
    SocketError(io::Error)
}

impl From<io::Error> for UpdateError {
    fn from(err: io::Error) -> UpdateError {
        UpdateError::SocketError(err)
    }
}

impl From<packet::ChallengeEncodeError> for UpdateError {
    fn from(err: packet::ChallengeEncodeError) -> UpdateError {
        UpdateError::Internal(InternalError::ChallengeEncodeError(err))
    }
}

impl From<SendError> for UpdateError {
    fn from(err: SendError) -> UpdateError {
        UpdateError::SendError(err)
    }
}

impl From<packet::PacketError> for SendError {
    fn from(err: packet::PacketError) -> SendError {
        SendError::PacketEncodeError(err)
    }
}

impl From<io::Error> for SendError {
    fn from(err: io::Error) -> SendError {
        SendError::SocketError(err)
    }
}

pub type ClientId = u64;

/// Enum that describes and event from the server.
pub enum ServerEvent {
    /// A client has connected, contains a reference to the client that was just created. `out_packet` contains private date from token.
    ClientConnect(ClientId),
    /// A client has disconnected, contains the clien that was just disconnected.
    ClientDisconnect(ClientId),
    /// Called when client tries to connect but all slots are full.
    ClientSlotFull,
    /// We recieved a packet, `out_packet` will be filled with data based on `usize`, contains a reference to the client that reieved the packet.
    Packet(ClientId, usize)
}

pub type UdpServer = Server<mio::udp::UdpSocket>;

const SERVER_TOKEN: mio::Token = mio::Token(0);
const RETRY_TIMEOUT: f64 = 1.0;

pub struct Server<I> {
    listen_socket: I,
    listen_addr: SocketAddr,
    event_queue: mio::Poll,
    event_list: mio::Events,
    protocol_id: u64,
    connect_key: [u8; NETCODE_KEY_BYTES],
    //@todo: We could probably use a free list or something smarter here if
    //we find that performance is an issue.
    clients: Vec<Option<(Connection, I)>>,
    time: f64,

    send_sequence: u64,

    challenge_sequence: u64,
    challenge_key: [u8; NETCODE_KEY_BYTES],

    client_event_idx: usize,
    io_event_idx: usize
}

impl<I> Server<I> where I: SocketProvider<I> + mio::Evented + Clone {
    /// Constructs a new Server bound to `local_addr` with `max_clients` and supplied `private_key` for authentication.
    pub fn new<A>(local_addr: A, max_clients: usize, protocol_id: u64, private_key: &[u8; NETCODE_KEY_BYTES]) -> Result<Server<I>, CreateError> where A: ToSocketAddrs {
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
                    protocol_id: protocol_id,
                    connect_key: key_copy,
                    clients: clients,
                    time: 0.0,
                    send_sequence: 0,
                    challenge_sequence: 0,
                    challenge_key: crypto::generate_key(),
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
    pub fn next_event(&mut self, out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
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
                Some(ref mut c) => Server::tick_client(self.time, c),
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

    fn handle_io(&mut self, io_event: mio::Event, out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
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
                    let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
                    socket.recv(&mut scratch)
                        .map_err(|e| e.into())
                        .and_then(|read| {
                            Self::handle_packet(time, (client, socket), &scratch[..read.unwrap_or(0)], out_packet)
                        })
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn handle_client_connect(&mut self, out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
        match self.listen_socket.recv_from(&mut scratch)? {
            Some((size, addr)) => {
                info!("Accepting connection from {}", &addr);

                if let Some(private_data) = Self::validate_client_token(self.protocol_id, &self.connect_key, &scratch[..size], out_packet) {
                   //See if we already have this connection
                    if let Some(idx) = self.find_client_by_id(private_data.client_id) {
                        if let Some((ref mut client,_)) = self.clients[idx] {
                            match client.state {
                                ConnectionState::PendingResponse(ref mut retry) => {
                                    retry.last_retry = 0.0;
                                    retry.retry_count += 1;
                                }
                                _ => ()
                            }
                        }
                    } else {
                        //Find open index
                        match self.clients.iter().position(|v| v.is_none()) {
                            Some(idx) => {
                                use std::str::FromStr;
                                //@todo: pick ipv6 if we are using ipv6
                                let bind_addr = format!("0.0.0.0:{}", self.listen_addr.port());
                                let mut socket = I::bind(&SocketAddr::from_str(bind_addr.as_str()).unwrap())?;
                                socket.connect(addr)?;

                                let conn = Connection {
                                    client_id: private_data.client_id,
                                    state: ConnectionState::PendingResponse(RetryState::new(self.time)),
                                    server_to_client_key: private_data.server_to_client_key,
                                    client_to_server_key: private_data.client_to_server_key,
                                    addr: addr,
                                };

                                self.clients[idx] = Some((conn.clone(), socket));
                                trace!("Accepted connection");
                            },
                            None => {
                                trace!("Tried to accept new client but max clients connected: {}", self.clients.len());
                                return Ok(Some(ServerEvent::ClientSlotFull))
                            }
                        }
                    }

                    self.challenge_sequence += 1;

                    let challenge = packet::ChallengePacket::generate(
                        private_data.client_id,
                        &private_data.user_data,
                        self.challenge_sequence,
                        &self.challenge_key)?;

                    //Send challenge token
                    self.send_packet(private_data.client_id, &packet::Packet::Challenge(challenge))?;

                    Ok(Some(ServerEvent::ClientConnect(private_data.client_id)))
                } else {
                    trace!("Failed to accept client connection");
                    Ok(None)
                }
            },
            None => Ok(None)
        }
    }

    fn send_packet(&mut self, client_id: ClientId, packet: &packet::Packet) -> Result<(), SendError> {
        self.send_sequence += 1;

        let sequence = self.send_sequence;
        let protocol_id = self.protocol_id;

        if let Some(&mut Some((ref client, ref mut socket))) = self.find_client_by_id(client_id).map(|v| &mut self.clients[v]) {
            let mut out_packet = [0; NETCODE_MAX_PACKET_SIZE];
            packet::encode(&mut out_packet[..], 
                            protocol_id,
                            &packet,
                            Some((sequence, &client.server_to_client_key)),
                            None)?;

           socket.send(&out_packet[..]).map(|_| ()).map_err(|e| e.into())
        } else {
            trace!("Tried to send packet to invalid client id: {}", client_id);
            Err(SendError::InvalidClientId)
        }
    }

    fn validate_client_token(
            protocol_id: u64,
            private_key: &[u8; NETCODE_KEY_BYTES],
            packet: &[u8],
            out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Option<token::PrivateData> {
        match packet::decode(packet, protocol_id, None, out_packet) {
            Ok(packet) => match packet {
                packet::Packet::ConnectionRequest(req) => {
                    if req.version != *NETCODE_VERSION_STRING {
                        trace!("Version mismatch expected {:?} but got {:?}", 
                            NETCODE_VERSION_STRING, req.version);

                        return None;
                    }

                    let now = token::get_time_now();
                    if now > req.token_expire {
                        trace!("Token expired: {} > {}", now, req.token_expire);
                        return None;
                    }

                    if let Ok(v) = token::PrivateData::decode(&req.private_data, protocol_id, req.token_expire, req.sequence, private_key) {
                        //Validate hosts

                        Some(v)
                    } else {
                        info!("Unable to decode connection token");
                        None
                    }
                },
                packet => {
                    trace!("Expected Connection Request but got packet type {}", packet.get_type_id());
                    None
                }
            },
            Err(e) => {
                trace!("Failed to decode connect packet: {:?}", e);
                None
            }
        }
    }

    fn tick_client(time: f64, client: &mut (Connection, I)) -> (bool, Option<Result<ServerEvent, UpdateError>>) {
        let client_id = 0;
        let (new_state, result) = match &mut client.0.state {
            &mut ConnectionState::PendingResponse(ref mut retry_state) => {
                let result = Self::process_timeout(time, retry_state, &mut client.1, |_socket| {
                    //We let client connection tokens drive retry so do nothing here
                });

                //If we didn't timeout then persist our retry state
                if result {
                    (None, (false, None))
                } else {    //Timed out, remove client and trigger event
                    (Some(ConnectionState::TimedOut), (true, Some(Ok(ServerEvent::ClientDisconnect(client_id)))))
                }
            },
            &mut ConnectionState::Idle(ref mut retry_state) => {
                let result = Self::process_timeout(time, retry_state, &mut client.1, |socket| {
                });

                //If we didn't timeout then persist our retry state
                if result {
                    (None, (false, None))
                } else {    //Timed out, remove client and trigger event
                    (Some(ConnectionState::TimedOut), (false, Some(Ok(ServerEvent::ClientDisconnect(client_id)))))
                }
            },
            &mut ConnectionState::Connected => { 
                (Some(ConnectionState::Idle(RetryState::new(time))), (false, None))
            },
            &mut ConnectionState::TimedOut 
                | &mut ConnectionState::Disconnected => (None, (true, None)),
        };

        //If we're moving to a new state update it here
        if let Some(new_state) = new_state {
            client.0.state = new_state;
        }

        result
    }

    fn process_timeout<S>(time: f64, state: &mut RetryState, socket: &mut I, send_func: S) -> bool where S: Fn(&mut I) {
        if state.last_update + NETCODE_TIMEOUT_SECONDS as f64 <= time {
            false
        } else {
            //Retry if we've hit an expire timeout or if this is the first time we're ticking.
            if state.last_retry > RETRY_TIMEOUT
                || (state.last_retry == 0.0 && state.retry_count == 0) {
                send_func(socket);
                state.last_retry = 0.0;
            }

            true
        }
    }

    fn handle_packet(time: f64,
            (client, socket): (&mut Connection, &mut I),
            packet: &[u8],
            out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE])
                -> Result<Option<ServerEvent>, UpdateError> {
        if packet.len() == 0 {
            return Ok(None)
        }

        //Update client state with any recieved packet
        client.state = match client.state.clone() {
            ConnectionState::Connected => ConnectionState::Idle(RetryState::new(time)),
            ConnectionState::Idle(_) => ConnectionState::Idle(RetryState::new(time)),
            ConnectionState::PendingResponse(_) => ConnectionState::Connected,
            s => s
        };

        Ok(Some(ServerEvent::Packet(client.client_id, 0)))
    }

    fn find_client_by_id(&self, id: ClientId) -> Option<usize> {
        self.clients.iter().position(|v| v.as_ref().map_or(false, |&(ref c,_)| c.client_id == id))
    }

    fn find_client_by_addr(&self, addr: &SocketAddr) -> Option<usize> {
        self.clients.iter().position(|v| v.as_ref().map_or(false, |&(ref c,_)| c.addr == *addr))
    }
}