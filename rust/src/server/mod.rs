//! This module holds a netcode.io server implemenation and all of its related functions.

use std::net::{ToSocketAddrs, SocketAddr, UdpSocket};
use std::io;
#[cfg(test)]
use std::time::Duration;

use common::*;
use packet;
use token;
use crypto;

mod connection;
use server::connection::*;
use socket::*;
use error::*;
use channel::{self, Channel};

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

pub type ClientId = u64;

/// Describes event the server receives when calling `next_event(..)`.
#[derive(Debug)]
pub enum ServerEvent {
    /// A client has connected, contains a reference to the client that was just created. `out_packet` contains private user data from token.
    ClientConnect(ClientId),
    /// A client has disconnected, contains the client that was just disconnected.
    ClientDisconnect(ClientId),
    /// Called when client tries to connect but all slots are full.
    ClientSlotFull,
    /// We received a packet, `out_packet` will be filled with data based on `usize`, contains the client id that reieved the packet and length of the packet.
    Packet(ClientId, usize),
    /// We received a keep alive packet with included client id.
    SentKeepAlive(ClientId),
    /// Client failed connection token validation
    RejectedClient,
    /// Replay detection heard duplicate packet and rejected it.
    ReplayRejected(ClientId)
}

/// UDP based netcode server.
pub type UdpServer = Server<UdpSocket,()>;

type ClientVec = Vec<Option<Connection>>;

/// Netcode server object.
/// # Example
/// ```rust
/// use netcode::{UdpServer, ServerEvent};
///
/// fn run_server() {
///     const PROTOCOL_ID: u64 = 0xFFEE;
///     const MAX_CLIENTS: usize = 32;
///     let mut server = UdpServer::new("127.0.0.1:0",
///                                     MAX_CLIENTS,
///                                     PROTOCOL_ID,
///                                     &netcode::generate_key()).unwrap();
///
///     loop {
///         server.update(1.0 / 10.0);
///         let mut packet_data = [0; netcode::NETCODE_MAX_PAYLOAD_SIZE];
///         match server.next_event(&mut packet_data) {
///             Ok(Some(e)) => {
///                 match e {
///                     ServerEvent::ClientConnect(_id) => {},
///                     ServerEvent::ClientDisconnect(_id) => {},
///                     ServerEvent::Packet(_id,_size) => {},
///                     _ => ()
///                 }
///             },
///             Ok(None) => (),
///             Err(err) => Err(err).unwrap()
///         }
///
///         //Tick world/gamestate/etc.
///         //Sleep till next frame.
///     }
/// }
/// ```
pub struct Server<I,S> {
    //@todo: We could probably use a free list or something smarter here if
    //we find that performance is an issue.
    clients: ClientVec,
    internal: ServerInternal<I,S>
}

struct ServerInternal<I,S> {
    #[allow(dead_code)]
    socket_state: S,

    listen_socket: I,
    listen_addr: SocketAddr,

    protocol_id: u64,
    connect_key: [u8; NETCODE_KEY_BYTES],

    time: f64,

    challenge_sequence: u64,
    challenge_key: [u8; NETCODE_KEY_BYTES],

    client_event_idx: usize,

    token_sequence: u64,
}

enum TickResult {
    Noop,
    StateChange(ConnectionState),
    SendKeepAlive
}

impl<I,S> Server<I,S> where I: SocketProvider<I,S> {
    /// Constructs a new Server bound to `local_addr` with `max_clients` and supplied `private_key` for authentication.
    pub fn new<A>(local_addr: A, max_clients: usize, protocol_id: u64, private_key: &[u8; NETCODE_KEY_BYTES])
            -> Result<Server<I,S>, CreateError>
            where A: ToSocketAddrs {
        let bind_addr = local_addr.to_socket_addrs().unwrap().next().unwrap();
        let mut socket_state = I::new_state();
        match I::bind(&bind_addr, &mut socket_state) {
            Ok(s) => {
                let mut key_copy: [u8; NETCODE_KEY_BYTES] = [0; NETCODE_KEY_BYTES];
                key_copy.copy_from_slice(private_key);

                let mut clients = Vec::with_capacity(max_clients);
                for _ in 0..max_clients {
                    clients.push(None);
                }

                trace!("Started server on {:?}", s.local_addr().unwrap());

                Ok(Server {
                    clients: clients,
                    internal: ServerInternal {
                        socket_state: socket_state,
                        listen_socket: s,
                        listen_addr: bind_addr,
                        protocol_id: protocol_id,
                        connect_key: key_copy,
                        time: 0.0,
                        challenge_sequence: 0,
                        challenge_key: crypto::generate_key(),
                        client_event_idx: 0,
                        token_sequence: 0
                    }
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

    /// Generates a connection token with `client_id` that expires after `expire_secs` with an optional user_data.
    pub fn generate_token(&mut self, expire_secs: usize, client_id: u64, user_data: Option<&[u8; NETCODE_USER_DATA_BYTES]>) -> Result<token::ConnectToken, token::GenerateError> {
        self.internal.token_sequence += 1;

        let addr = if self.internal.listen_addr.port() == 0 {
            self.get_local_addr()?
        } else {
            self.internal.listen_addr
        };

        token::ConnectToken::generate(
            [addr].iter().cloned(),
            &self.internal.connect_key,
            expire_secs,
            self.internal.token_sequence,
            self.internal.protocol_id,
            client_id,
            user_data)
    }

    /// Gets the local port that this server is bound to.
    pub fn get_local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.internal.listen_socket.local_addr()
    }

    /// Sends a packet to `client_id` specified.
    pub fn send(&mut self, client_id: ClientId, packet: &[u8]) -> Result<usize, SendError> {
        if packet.len() == 0 || packet.len() > NETCODE_MAX_PAYLOAD_SIZE {
            return Err(SendError::PacketSize)
        }

        if let Some(client) = Self::find_client_by_id(&mut self.clients, client_id) {
            trace!("Sending packet to {} with length {}", client_id, packet.len());
            self.internal.send_packet(client, &packet::Packet::Payload(packet.len()), Some(packet))
        } else {
            trace!("Unable to send packet, invalid client id {}", client_id);
            Err(SendError::InvalidClientId)
        }
    }

    /// Updates time elapsed since last server iteration.
    pub fn update(&mut self, elapsed: f64) {
        self.internal.update(elapsed);
    }

    /// Checks for incoming packets, client connection and disconnections. Returns `None` when no more events
    /// are pending.
    pub fn next_event(&mut self, out_packet: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        if out_packet.len() < NETCODE_MAX_PAYLOAD_SIZE {
            return Err(UpdateError::PacketBufferTooSmall)
        }

        loop {
            let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
            let result = match self.internal.listen_socket.recv_from(&mut scratch) {
                Ok((len, addr)) => self.handle_io(&addr, &scratch[..len], out_packet),
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    _ => Err(RecvError::SocketError(e).into())
                }
            };

            if let Ok(None) = result {
                break;
            } else {
                return result
            }
        }

        loop {
            if self.internal.client_event_idx >= self.clients.len() {
                break;
            }

            let clients = &mut self.clients;
            let result = if let Some(client) = clients[self.internal.client_event_idx].as_mut() {
                self.internal.tick_client(client)?
            } else {
                TickResult::Noop
            };

            let event = match result {
                TickResult::Noop => None,
                TickResult::StateChange(state) => {
                    match state {
                        ConnectionState::TimedOut |
                        ConnectionState::Disconnected => {
                            let client_id = clients[self.internal.client_event_idx].as_ref().map_or(0, |c| c.client_id);
                            clients[self.internal.client_event_idx] = None;
                            trace!("Client disconnected {}", client_id);
                            Some(ServerEvent::ClientDisconnect(client_id))
                        },
                        _ => {
                            if let Some(client) = clients[self.internal.client_event_idx].as_mut() {
                                client.state = state.clone();
                            }

                            None
                        }
                    }
                },
                TickResult::SendKeepAlive => {
                    let client_id = clients[self.internal.client_event_idx].as_ref().map_or(0, |c| c.client_id);
                    Some(ServerEvent::SentKeepAlive(client_id))
                }
            };

            self.internal.client_event_idx += 1;

            if event.is_some() {
                return event.map_or(Ok(None), |r| Ok(Some(r)))
            }
        }

        Ok(None)
    }

    /// Sends a disconnect and removes client.
    pub fn disconnect(&mut self, client_id: ClientId) -> Result<(), SendError> {
        if let Some(client) = Self::find_client_by_id(&mut self.clients, client_id) {
            self.internal.handle_client_disconnect(client)?;
        }

        let idx = self.clients.iter().position(|c| c.as_ref().map_or(false, |c| c.client_id == client_id));

        if let Some(idx) = idx {
            self.clients[idx] = None;
        }

        Ok(())
    }

    fn handle_io(&mut self, addr: &SocketAddr, data: &[u8], payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        let result = if let Some(client) = Self::find_client_by_addr(&mut self.clients, addr) {
            //Make sure we aren't still trying to connect
            trace!("New data on client socket {} {:?}", client.client_id, client.channel.get_addr());
            Some(self.internal.handle_packet(client, data, payload))
        } else {
            None
        };

        //If we didn't have an existing client then handle a new client
        result.unwrap_or_else(|| self.internal.handle_new_client(addr, data, payload, &mut self.clients))
    }

    fn find_client_by_id<'a>(clients: &'a mut ClientVec, id: ClientId) -> Option<&'a mut Connection> {
        clients.iter_mut().map(|c| c.as_mut()).find(|c| {
                if let &Some(ref c) = c {
                    c.client_id == id
                } else {
                    false
                }
            })
            .and_then(|c| c)
    }

    fn find_client_by_addr<'a>(clients: &'a mut ClientVec, addr: &SocketAddr) -> Option<&'a mut Connection> {
        clients.iter_mut().map(|c| c.as_mut()).find(|c| {
                if let &Some(ref c) = c {
                    c.channel.get_addr() == addr
                } else {
                    false
                }
            })
            .and_then(|c| c)
    }

    #[cfg(test)]
    pub fn get_socket_state(&mut self) -> &mut S {
        &mut self.internal.socket_state
    }

    #[cfg(test)]
    pub fn set_read_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error> {
        self.internal.listen_socket.set_recv_timeout(duration)
    }
}

impl<I,S> ServerInternal<I,S> where I: SocketProvider<I,S> {
    fn update(&mut self, elapsed: f64) {
        self.time += elapsed;
        self.client_event_idx = 0;
    }

    fn handle_client_connect(&mut self, addr: &SocketAddr, request: &packet::ConnectionRequestPacket, clients: &mut ClientVec) -> Result<Option<ServerEvent>, UpdateError> {
        if let Some(ref private_data) = self.validate_client_token(request) {
            //See if we already have this connection
            let existing_client_result = if let Some(client) = Server::<I,S>::find_client_by_id(clients, private_data.client_id) {
                trace!("Client already exists, skipping socket creation");
                Some(self.send_client_challenge(client, private_data).map(|_| None))
            } else {
                None
            };

            existing_client_result.unwrap_or_else(|| {
                //Find open index
                match clients.iter().position(|v| v.is_none()) {
                    Some(idx) => {
                        let mut conn = Connection {
                            client_id: private_data.client_id,
                            state: ConnectionState::PendingResponse,
                            channel: Channel::new(&private_data.server_to_client_key, &private_data.client_to_server_key, addr, self.protocol_id, idx, clients.len(), self.time)
                        };

                        self.send_client_challenge(&mut conn, private_data)?;

                        trace!("Accepted connection {:?}", addr);
                        clients[idx] = Some(conn);

                        Ok(None)
                    },
                    None => {
                        self.send_denied_packet(&addr, &private_data.server_to_client_key)?;
                        trace!("Tried to accept new client but max clients connected: {}", clients.len());
                        return Ok(Some(ServerEvent::ClientSlotFull))
                    }
                }
            })
        } else {
            trace!("Failed to accept client connection");
            Ok(Some(ServerEvent::RejectedClient))
        }
    }

    fn send_client_challenge(&mut self, client: &mut Connection, private_data: &token::PrivateData) -> Result<(), UpdateError> {
        self.challenge_sequence += 1;

        trace!("Sending challenge packet");

        let challenge = packet::ChallengePacket::generate(
            private_data.client_id,
            &private_data.user_data,
            self.challenge_sequence,
            &self.challenge_key)?;

        //Send challenge token
        self.send_packet(client, &packet::Packet::Challenge(challenge), None)?;

        Ok(())
    }

    fn send_packet(&mut self, client: &mut Connection, packet: &packet::Packet, payload: Option<&[u8]>) -> Result<usize, SendError> {
        client.channel.send(self.time, packet, payload, &mut self.listen_socket)
    }

    fn send_denied_packet(&mut self, addr: &SocketAddr, key: &[u8; NETCODE_KEY_BYTES]) -> Result<(), SendError> {
        //id + sequence
        let mut packet = [0; 1 + 8];
        packet::encode(&mut packet[..], self.protocol_id, &packet::Packet::ConnectionDenied, Some((0, key)), None)?;

        self.listen_socket.send_to(&packet[..], addr).map_err(|e| e.into()).map(|_| ())
    }

    fn validate_client_token(&mut self, req: &packet::ConnectionRequestPacket) -> Option<token::PrivateData> {
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

        if let Ok(v) = token::PrivateData::decode(&req.private_data, self.protocol_id, req.token_expire, req.sequence, &self.connect_key) {
            let has_host = v.hosts.get().any(|thost| {
                    thost == self.listen_addr || (self.listen_addr.port() == 0 && thost.ip() == self.listen_addr.ip())
                });

            if !has_host {
                info!("Client connected but didn't contain host's address.");
                None
            } else {
                Some(v)
            }
        } else {
            info!("Unable to decode connection token");
            None
        }
   }

    fn tick_client(&mut self, client: &mut Connection) -> Result<TickResult, UpdateError> {
        let state = &client.state;
        let result = match *state {
            ConnectionState::PendingResponse => {
                match client.channel.update(self.time, &mut self.listen_socket, false)? {
                    channel::UpdateResult::Expired => {
                        trace!("Failed to hear from client {}, timed out", client.client_id);
                        TickResult::StateChange(ConnectionState::TimedOut)
                    },
                    channel::UpdateResult::SentKeepAlive => TickResult::Noop,
                    channel::UpdateResult::Noop => TickResult::Noop
                }
            },
            ConnectionState::Idle => {
                match client.channel.update(self.time, &mut self.listen_socket, true)? {
                    channel::UpdateResult::Expired => {
                        trace!("Failed to hear from client {}, timed out", client.client_id);
                        TickResult::StateChange(ConnectionState::TimedOut)
                    },
                    channel::UpdateResult::SentKeepAlive => {
                        trace!("Sent keep alive to client {}", client.client_id);
                        TickResult::SendKeepAlive
                    },
                    channel::UpdateResult::Noop => TickResult::Noop
                }
            },
            ConnectionState::TimedOut | ConnectionState::Disconnected => TickResult::Noop
        };

        Ok(result)
    }

    fn handle_new_client(&mut self, addr: &SocketAddr, data: &[u8], payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE], clients: &mut ClientVec) -> Result<Option<ServerEvent>, UpdateError> {
        trace!("New data on listening socket");

        match packet::decode(data, self.protocol_id, None, payload) {
            Ok(packet) => match packet.1 {
                packet::Packet::ConnectionRequest(req) => self.handle_client_connect(addr, &req, clients),
                packet => {
                    trace!("Expected Connection Request but got packet type {}", packet.get_type_id());
                    Ok(None)
                }
            },
            Err(e) => {
                trace!("Failed to decode connect packet: {:?}", e);
                Ok(None)
            }
        }
    }

    fn handle_client_disconnect(&mut self, client: &mut Connection) -> Result<(), SendError> {
        trace!("Disconnecting client {}", client.client_id);

        self.send_packet(client, &packet::Packet::Disconnect, None)?;
        client.state = ConnectionState::Disconnected;

        Ok(())
    }

    fn handle_packet(&mut self,
            client: &mut Connection,
            packet: &[u8],
            out_packet: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE])
                -> Result<Option<ServerEvent>, UpdateError> {
        if packet.len() == 0 {
            return Ok(None)
        }

        trace!("Handling packet from client");
        let decoded = match client.channel.recv(self.time, packet, out_packet) {
            Ok(packet) => packet,
            Err(RecvError::DuplicateSequence) => return Ok(Some(ServerEvent::ReplayRejected(client.client_id))),
            Err(e) => {
                info!("Failed to decode packet: {:?}", e);
                client.state = ConnectionState::Disconnected;

                return Ok(Some(ServerEvent::ClientDisconnect(client.client_id)))
            }
        };

        //Update client state with any recieved packet
        let mut state = None;
        let event = match client.state {
            ConnectionState::Idle => {
                match decoded {
                    packet::Packet::Payload(len) => {
                        trace!("Received payload packet from {} with size {}", client.client_id, len);
                        Some(ServerEvent::Packet(client.client_id, len))
                    },
                    packet::Packet::KeepAlive(_) => {
                        trace!("Heard keep alive from client {}", client.client_id);
                        Some(ServerEvent::SentKeepAlive(client.client_id))
                    },
                    packet::Packet::Disconnect => {
                        trace!("Received disconnect from client {}", client.client_id);
                        state = Some(ConnectionState::Disconnected);
                        Some(ServerEvent::ClientDisconnect(client.client_id))
                    },
                    other => {
                        info!("Unexpected packet type {}", other.get_type_id());
                        None
                    }
                }
             },
            ConnectionState::PendingResponse => {
                match decoded {
                    packet::Packet::Response(resp) => {
                        let token = resp.decode(&self.challenge_key)?;
                        out_packet[..NETCODE_USER_DATA_BYTES].copy_from_slice(&token.user_data);

                        client.channel.send_keep_alive(self.time, &mut self.listen_socket)?;

                        info!("client response");

                        state = Some(ConnectionState::Idle);
                        Some(ServerEvent::ClientConnect(token.client_id))
                    },
                    packet::Packet::ConnectionRequest(ref req) => {
                        if let Some(ref private_data) = self.validate_client_token(req) {
                            self.send_client_challenge(client, private_data).map(|_| None)?
                        } else {
                            None
                        }
                    },
                    p => {
                        info!("Unexpected packet type when waiting for response {}", p.get_type_id());
                        None
                    }
                }
            },
            _ => None
        };

        if let Some(state) = state {
            client.state = state;
        }

        Ok(event)
    }
}

#[cfg(test)]
mod test {
    use common::*;
    use packet::*;
    use token;
    use super::*;

    use std::net::UdpSocket;

    const PROTOCOL_ID: u64 = 0xFFCC;
    const MAX_CLIENTS: usize = 256;
    const CLIENT_ID: u64 = 0xFFEEDD;

    struct TestHarness<I,S> where I: SocketProvider<I,S> {
        next_sequence: u64,
        server: Server<I,S>,
        private_key: [u8; NETCODE_KEY_BYTES],
        socket: I,
        connect_token: token::ConnectToken
    }

    impl<S,I> TestHarness<I,S> where I: SocketProvider<I,S> {
        pub fn new(port: Option<u16>) -> TestHarness<I,S> {
            let private_key = crypto::generate_key();

            let addr = format!("127.0.0.1:{}", port.unwrap_or(0));
            let mut server = Server::<I,S>::new(&addr, MAX_CLIENTS, PROTOCOL_ID, &private_key).unwrap();
            server.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            let socket = I::bind(&Self::str_to_addr(&addr), server.get_socket_state()).unwrap();

            TestHarness {
                next_sequence: 0,
                server: server,
                private_key: private_key,
                socket: socket,
                connect_token: Self::generate_connect_token(&private_key, addr.as_str())
            }
        }

        fn str_to_addr(addr: &str) -> SocketAddr {
            use std::str::FromStr;
            SocketAddr::from_str(addr).unwrap()
        }

        pub fn generate_connect_token(private_key: &[u8; NETCODE_KEY_BYTES], addr: &str) -> token::ConnectToken {
            token::ConnectToken::generate(
                                [Self::str_to_addr(addr)].iter().cloned(),
                                private_key,
                                30, //Expire
                                0,
                                PROTOCOL_ID,
                                CLIENT_ID, //Client Id
                                None).unwrap()
        }

        pub fn replace_connect_token(&mut self, addr: &str, key: Option<&[u8; NETCODE_KEY_BYTES]>) {
            self.connect_token = Self::generate_connect_token(key.unwrap_or(&self.private_key), addr);
        }

        pub fn get_socket_state(&mut self) -> &mut S {
            self.server.get_socket_state()
        }

        pub fn get_connect_token(&mut self) -> &token::ConnectToken {
            &self.connect_token
        }

        fn get_next_sequence(&mut self) -> u64 {
            self.next_sequence += 1;
            self.next_sequence
        }

        pub fn send_connect_packet(&mut self) {
            let mut private_data = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
            private_data.copy_from_slice(&self.connect_token.private_data);

            let packet = Packet::ConnectionRequest(ConnectionRequestPacket {
                version: NETCODE_VERSION_STRING.clone(),
                protocol_id: PROTOCOL_ID,
                token_expire: self.connect_token.expire_utc,
                sequence: self.connect_token.sequence,
                private_data: private_data
            });

            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            let len = packet::encode(&mut data, PROTOCOL_ID, &packet, None, None).unwrap();
            self.socket.send_to(&data[..len], &self.server.get_local_addr().unwrap()).unwrap();
        }

        fn validate_challenge(&mut self) {
            let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            self.server.update(0.0);
            self.server.next_event(&mut data).unwrap();
        }

        fn read_challenge(&mut self) -> ChallengePacket {
            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            self.socket.set_recv_timeout(Some(Duration::from_secs(15))).unwrap();
            let (read, _) = self.socket.recv_from(&mut data).unwrap();

            let mut packet_data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            match packet::decode(&data[..read], PROTOCOL_ID, Some(&self.connect_token.server_to_client_key), &mut packet_data).unwrap() {
                (_, Packet::Challenge(packet)) => {
                    packet
                },
                _ => {
                    assert!(false);
                    ChallengePacket {
                        token_sequence: 0,
                        token_data: [0; NETCODE_CHALLENGE_TOKEN_BYTES]
                    }
                }
            }
        }

        fn send_response(&mut self, token: ChallengePacket) {
            let packet = Packet::Response(ResponsePacket {
                token_sequence: token.token_sequence,
                token_data: token.token_data
            });

            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            let len = packet::encode(&mut data, PROTOCOL_ID, &packet, Some((self.get_next_sequence(), &self.connect_token.client_to_server_key)), None).unwrap();
            self.socket.send_to(&data[..len], &self.server.get_local_addr().unwrap()).unwrap();
        }

        fn validate_response(&mut self) {
            let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            self.server.update(0.0);
            let event = self.server.next_event(&mut data);

            match event {
                Ok(Some(ServerEvent::ClientConnect(CLIENT_ID))) => (),
                e => assert!(false, "{:?}", e)
            }

            let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
            let (keep_alive, _) = self.socket.recv_from(&mut scratch).unwrap();
            match packet::decode(&scratch[..keep_alive], PROTOCOL_ID, Some(&self.connect_token.server_to_client_key), &mut data).unwrap() {
                (_, Packet::KeepAlive(_)) => (),
                (_, p) => assert!(false, "{:?}", p.get_type_id())
            }
        }

        fn generate_payload_packet(&mut self, payload: &[u8]) -> (usize, [u8; NETCODE_MAX_PACKET_SIZE]) {
            let packet = Packet::Payload(payload.len());

            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            let len = packet::encode(&mut data, PROTOCOL_ID, &packet, Some((self.get_next_sequence(), &self.connect_token.client_to_server_key)), Some(payload)).unwrap();

            (len, data)
        }

        fn send_payload(&mut self, payload: &[u8]) {
            let (len, data) = self.generate_payload_packet(payload);
            self.socket.send_to(&data[..len], &self.server.get_local_addr().unwrap()).unwrap();
        }

        fn validate_recv_payload(&mut self, payload: &[u8]) {
            self.server.update(0.0);
            let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];

            loop {
                match self.server.next_event(&mut data) {
                    Ok(Some(ServerEvent::Packet(cid, len))) => {
                        assert_eq!(cid, CLIENT_ID);
                        assert_eq!(payload.len(), len);
                        for i in 0..len {
                            assert_eq!(payload[i], data[i]);
                        }

                        break;
                    },
                    Ok(Some(ServerEvent::SentKeepAlive(cid))) => {
                        assert_eq!(cid, CLIENT_ID);
                    },
                    o => assert!(false, "unexpected {:?}", o)
                }
            }
        }

        fn validate_send_payload(&mut self, payload: &[u8]) {
            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            self.socket.set_recv_timeout(Some(Duration::from_secs(15))).unwrap();
            let (read,_) = self.socket.recv_from(&mut data).unwrap();

            let mut packet_data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            match packet::decode(&data[..read], PROTOCOL_ID, Some(&self.connect_token.server_to_client_key), &mut packet_data) {
                Ok((sequence, Packet::Payload(len))) => {
                    assert_eq!(sequence, self.next_sequence);
                    assert_eq!(payload.len(), len);
                    for i in 0..len {
                        assert_eq!(packet_data[i], payload[i]);
                    }
                },
                Ok((_,p)) => assert!(false, "unexpected packet type {}", p.get_type_id()),
                Err(o) => assert!(false, "unexpected {:?}", o)
            }

        }
    }

    #[allow(dead_code)]
    fn enable_logging() {
        use env_logger::LogBuilder;
        use log::LogLevelFilter;

        LogBuilder::new().filter(None, LogLevelFilter::Trace).init().unwrap();

        use capi::*;
        unsafe {
            netcode_log_level(NETCODE_LOG_LEVEL_DEBUG as i32);
        }
    }

    #[test]
    fn test_connect_api() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        harness.send_connect_packet();
        harness.validate_challenge();
        let challenge = harness.read_challenge();
        harness.send_response(challenge);
        harness.validate_response();
    }

    #[test]
    fn test_connect_bad_host() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        let port = harness.server.get_local_addr().unwrap().port();
        harness.replace_connect_token(format!("0.0.0.0:{}", port).as_str(), None);
        harness.send_connect_packet();

        let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
        harness.server.update(0.0);
        match harness.server.next_event(&mut data) {
            Ok(Some(ServerEvent::RejectedClient)) => {},
            _ => assert!(false)
        }
    }

    #[test]
    fn test_connect_bad_key() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        let port = harness.server.get_local_addr().unwrap().port();
        harness.replace_connect_token(format!("127.0.0.1:{}", port).as_str(), Some(&crypto::generate_key()));
        harness.send_connect_packet();

        let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
        harness.server.update(0.0);
        match harness.server.next_event(&mut data) {
            Ok(Some(ServerEvent::RejectedClient)) => {},
            _ => assert!(false)
        }
    }

    #[test]
    fn test_replay_protection() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        harness.send_connect_packet();
        harness.validate_challenge();
        let challenge = harness.read_challenge();
        harness.send_response(challenge);
        harness.validate_response();

        let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
        for i in 0..NETCODE_MAX_PAYLOAD_SIZE {
            data[i] = i as u8;
        }

        let (plen, packet) = harness.generate_payload_packet(&data);
        harness.socket.send_to(&packet[..plen], harness.server.get_local_addr().unwrap()).unwrap();
        harness.validate_recv_payload(&data);

        harness.socket.send_to(&packet[..plen], harness.server.get_local_addr().unwrap()).unwrap();
        harness.server.update(0.0);
        let mut scratch = [0; NETCODE_MAX_PAYLOAD_SIZE];
        match harness.server.next_event(&mut scratch) {
            Ok(Some(ServerEvent::ReplayRejected(cid))) => assert_eq!(cid, CLIENT_ID),
            o => assert!(false, "unexpected {:?}", o)
        }
    }

    #[test]
    fn test_payload() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        harness.send_connect_packet();
        harness.validate_challenge();
        let challenge = harness.read_challenge();
        harness.send_response(challenge);
        harness.validate_response();

        for s in 1..NETCODE_MAX_PAYLOAD_SIZE {
            let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            for i in 0..s {
                data[i] = i as u8;
            }

            harness.send_payload(&data[..s]);
            harness.validate_recv_payload(&data[..s]);

            harness.server.send(CLIENT_ID, &data[..s]).unwrap();
            harness.validate_send_payload(&data[..s]);
        }
    }
/*
    #[test]
    fn test_capi_payload() {
        #[allow(unused_variables)]
        let lock = ::common::test::FFI_LOCK.lock().unwrap();

        use capi::*;
        use std::ffi::CString;

        let mut harness = TestHarness::<SimulatedSocket, SimulatorRef>::new(Some(1235));

        unsafe {
            //Establish connection
            netcode_init();

            let addr = CString::new("127.0.0.1:1234").unwrap();
            let sim = harness.get_socket_state().clone();
            let client = netcode_client_create_internal(::std::mem::transmute(addr.as_ptr()), 0.0, sim.borrow_mut().sim);

            let mut connect_token = vec!();
            harness.get_connect_token().write(&mut connect_token).unwrap();

            netcode_client_connect(client, ::std::mem::transmute(connect_token.as_ptr()));

            let mut time = 0.0;
            loop {
                netcode_network_simulator_update(sim.borrow_mut().sim, time);

                harness.server.update(1.0 / 10.0);
                loop {
                    let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
                    match harness.server.next_event(&mut data) {
                        Ok(None) => break,
                        Err(e) => assert!(false, "{:?}", e),
                        _ => (),
                    }
                }

                netcode_client_update(client, time);

                if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED as i32 {
                    break;
                }

                if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED as i32 {
                    break;
                }

                time += 1.0 / 10.0;
            }

            assert_eq!(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED as i32);

            //Test payloads
            for s in 1..NETCODE_MAX_PAYLOAD_SIZE {
                let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
                for i in 0..s {
                    data[i] = i as u8;
                }

                netcode_client_send_packet(client, data.as_mut_ptr(), s as i32);
                netcode_network_simulator_update(sim.borrow_mut().sim, time);

                harness.validate_recv_payload(&data[..s]);

                harness.server.send(CLIENT_ID, &data[..s]).unwrap();

                netcode_network_simulator_update(sim.borrow_mut().sim, time);
                netcode_client_update(client, 1.0 / 10.0);

                let mut clen: i32 = 0;
                let cpacket = netcode_client_receive_packet(client, &mut clen, ::std::ptr::null_mut());

                assert!(cpacket != ::std::ptr::null_mut());
                assert_eq!(clen, s as i32);

                let cslice: &[u8] = ::std::slice::from_raw_parts(cpacket as *const u8, clen as usize);
                for i in 0..s {
                    assert_eq!(cslice[i], data[i]);
                }

                netcode_client_free_packet(client, cpacket);
            }

            netcode_client_destroy(client);

            netcode_term();
        }
    }

    #[test]
    fn test_capi_connect() {
        #[allow(unused_variables)]
        let lock = ::common::test::FFI_LOCK.lock().unwrap();

        use capi::*;
        use std::ffi::CString;

        let mut harness = TestHarness::<SimulatedSocket, SimulatorRef>::new(Some(1235));

        unsafe {
            netcode_init();

            let addr = CString::new("127.0.0.1:1234").unwrap();
            let sim = harness.get_socket_state().clone();
            let client = netcode_client_create_internal(::std::mem::transmute(addr.as_ptr()), 0.0, sim.borrow_mut().sim);

            let mut connect_token = vec!();
            harness.get_connect_token().write(&mut connect_token).unwrap();

            netcode_client_connect(client, ::std::mem::transmute(connect_token.as_ptr()));

            let mut time = 0.0;
            loop {
                netcode_network_simulator_update(sim.borrow_mut().sim, time);

                harness.server.update(1.0 / 10.0);
                loop {
                    let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
                    match harness.server.next_event(&mut data) {
                        Ok(None) => break,
                        Err(e) => assert!(false, "{:?}", e),
                        _ => (),
                    }
                }

                netcode_client_update(client, time);

                if netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED as i32 {
                    break;
                }

                if netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED as i32 {
                    break;
                }

                time += 1.0 / 10.0;
            }

            assert_eq!(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED as i32);

            netcode_client_destroy(client);

            netcode_term();
       }
   }
   */
}
