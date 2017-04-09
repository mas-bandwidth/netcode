//! This module holds a netcode.io server implemenation and all of its related functions.

use std::net::{ToSocketAddrs, SocketAddr, UdpSocket};
use std::io;
use std::time::Duration;

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
#[derive(Debug)]
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

pub type UdpServer = Server<UdpSocket,()>;

const RETRY_TIMEOUT: f64 = 1.0;

pub struct Server<I,S> {
    socket_state: S,
    listen_socket: I,
    listen_addr: SocketAddr,
    protocol_id: u64,
    connect_key: [u8; NETCODE_KEY_BYTES],
    //@todo: We could probably use a free list or something smarter here if
    //we find that performance is an issue.
    clients: Vec<Option<Connection>>,
    time: f64,

    send_sequence: u64,

    challenge_sequence: u64,
    challenge_key: [u8; NETCODE_KEY_BYTES],

    client_event_idx: usize,
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
                    socket_state: socket_state,
                    listen_socket: s,
                    listen_addr: bind_addr,
                    protocol_id: protocol_id,
                    connect_key: key_copy,
                    clients: clients,
                    time: 0.0,
                    send_sequence: 0,
                    challenge_sequence: 0,
                    challenge_key: crypto::generate_key(),
                    client_event_idx: 0,
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

    pub fn get_socket_state(&mut self) -> &mut S {
        &mut self.socket_state
    }

    /// Gets the local port that this server is bound to.
    pub fn get_local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.listen_socket.local_addr()
    }

    pub fn get_challenge_key(&self) -> &[u8; NETCODE_KEY_BYTES] {
        &self.challenge_key
    }

    pub fn set_read_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error> {
        self.listen_socket.set_recv_timeout(duration)
    }

    /// Updates time elapsed since last server iteration.
    pub fn update(&mut self, elapsed: f64) -> Result<(), io::Error> {
        self.time += elapsed;
        self.client_event_idx = 0;

        Ok(())
    }
    
    /// Checks for incoming packets, client connection and disconnections. Returns `None` when no more events
    /// are pending.
    pub fn next_event(&mut self, out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        if out_packet.len() < NETCODE_MAX_PACKET_SIZE {
            return Err(UpdateError::PacketBufferTooSmall)
        }

        loop {
            let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
            let result = match self.listen_socket.recv_from(&mut scratch) {
                Ok((len, addr)) => self.handle_io(&addr, &scratch[..len], out_packet),
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    io::ErrorKind::Other => Ok(None),
                    _ => Err(e.into())
                }
            };

            if let Ok(None) = result {
                break;
            } else {
                return result
            }
        }

        loop {
            if self.client_event_idx >= self.clients.len() {
                break;
            }

            let result = match self.clients[self.client_event_idx] {
                Some(ref mut c) => Server::<I,S>::tick_client(self.time, c),
                None => TickResult::Noop
            };

            let event = match result {
                TickResult::Noop => None,
                TickResult::StateChange(state) => {
                    match state {
                        ConnectionState::TimedOut |
                        ConnectionState::Disconnected => {
                            let client_id = self.clients[self.client_event_idx].as_ref().map(|c| c.client_id).unwrap_or(0);
                            self.clients[self.client_event_idx] = None;
                            trace!("Client disconnected {}", client_id);
                            Some(ServerEvent::ClientDisconnect(client_id))
                        },
                        _ => {
                            if let Some(client) = self.clients[self.client_event_idx].as_mut() {
                                client.state = state.clone();
                            }

                            None
                        }
                    }
                },
                TickResult::SendKeepAlive => {
                    let client_idx = self.client_event_idx;
                    self.send_keepalive_packet(client_idx)?;
                    None
                }
            };

            self.client_event_idx += 1;

            if event.is_some() {
                return event.map_or(Ok(None), |r| Ok(Some(r)))
            }
        }

        Ok(None)
    }

    fn handle_io(&mut self, addr: &SocketAddr, data: &[u8], out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        match self.find_client_by_addr(addr) {
            None => {
                trace!("New data on listening socket");
                //Accept new client
                self.handle_client_connect(addr, data, out_packet)
            },
            Some(client_idx) => {
                let protocol_id = self.protocol_id;
                let challenge_key = self.challenge_key;

                trace!("New data on client socket {}", client_idx);

                if let Some(ref mut client) = self.clients[client_idx].as_mut() {
                    let time = self.time;
                    Self::handle_packet(time, protocol_id, &challenge_key, client, data, out_packet)
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn handle_client_connect(&mut self, addr: &SocketAddr, data: &[u8], out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE]) -> Result<Option<ServerEvent>, UpdateError> {
        if let Some(private_data) = Self::validate_client_token(self.protocol_id, &self.connect_key, data, out_packet) {
            //See if we already have this connection
            if let Some(idx) = self.find_client_by_id(private_data.client_id) {
                trace!("Client already exists, skipping socket creation");
                if let Some(ref mut client) = self.clients[idx] {
                    match client.state {
                        ConnectionState::PendingResponse(ref mut retry) => {
                            retry.last_response = self.time;
                        }
                        _ => ()
                    }
                }
            } else {
                //Find open index
                match self.clients.iter().position(|v| v.is_none()) {
                    Some(idx) => {
                        let conn = Connection {
                            client_id: private_data.client_id,
                            state: ConnectionState::PendingResponse(RetryState {
                                last_sent: 0.0,
                                last_response: self.time
                            }),
                            server_to_client_key: private_data.server_to_client_key,
                            client_to_server_key: private_data.client_to_server_key,
                            addr: addr.clone(),
                        };

                        trace!("Accepted connection {:?}", addr);
                        self.clients[idx] = Some(conn);
                    },
                    None => {
                        self.send_denied_packet(&addr, &private_data.server_to_client_key)?;
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
    }

    fn send_packet(&mut self, client_id: ClientId, packet: &packet::Packet) -> Result<(), SendError> {
        self.send_sequence += 1;

        let sequence = self.send_sequence;
        let protocol_id = self.protocol_id;

        let encode = if let Some(ref client) = self.find_client_by_id(client_id).and_then(|v| self.clients[v].as_ref()) {
            let mut out_packet = [0; NETCODE_MAX_PACKET_SIZE];
            let len = packet::encode(&mut out_packet[..], 
                            protocol_id,
                            &packet,
                            Some((sequence, &client.server_to_client_key)),
                            None)?;
            trace!("Sending packet with id {} and length {}", packet.get_type_id(), len);

            Ok((len, out_packet, client.addr))
        } else {
            trace!("Tried to send packet to invalid client id: {}", client_id);
            return Err(SendError::InvalidClientId)
        };

        encode.and_then(|(len, packet, addr)| {
            self.listen_socket.send_to(&packet[..len], &addr).map(|_| ()).map_err(|e| e.into())
        })
    }

    fn send_denied_packet(&mut self, addr: &SocketAddr, key: &[u8; NETCODE_KEY_BYTES]) -> Result<(), SendError> {
        self.send_sequence += 1;

        //id + sequence
        let mut packet = [0; 1 + 8];
        packet::encode(&mut packet[..], self.protocol_id, &packet::Packet::ConnectionDenied, Some((self.send_sequence, key)), None)?;

        self.listen_socket.send_to(&packet[..], addr).map_err(|e| e.into()).map(|_| ())
    }

    fn send_keepalive_packet(&mut self, client_idx: usize) -> Result<(), SendError> {
        let client_id = self.clients[client_idx].as_ref().map(|c| c.client_id).unwrap_or(0);
        trace!("Sending keepalive for {}", client_id);
        let client_count = self.clients.len() as i32;
        self.send_packet(client_id, &packet::Packet::KeepAlive(packet::KeepAlivePacket {
            client_idx: client_idx as i32,
            max_clients: client_count
        }))
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
                        //todo: Validate hosts

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

    fn tick_client(time: f64, client: &mut Connection) -> TickResult {
        match &mut client.state {
            &mut ConnectionState::PendingResponse(ref mut retry_state) => {
                //If we didn't timeout then persist our retry state
                if !retry_state.has_expired(time) {
                    TickResult::Noop
                } else {    //Timed out, remove client and trigger event
                    TickResult::StateChange(ConnectionState::TimedOut)
                }
            },
            &mut ConnectionState::Idle(ref mut retry_state) => {
                //If we didn't timeout then persist our retry state
                if !retry_state.has_expired(time) {
                    if retry_state.should_send_keepalive(time) {
                        *retry_state = retry_state.update_sent(time);
                        TickResult::SendKeepAlive
                    } else {
                        TickResult::Noop
                    }
                } else {    //Timed out, remove client and trigger event
                    TickResult::StateChange(ConnectionState::TimedOut)
                }
            },
            &mut ConnectionState::TimedOut 
                | &mut ConnectionState::Disconnected => TickResult::Noop
        }
    }

    fn handle_packet(time: f64,
            protocol_id: u64,
            challenge_key: &[u8; NETCODE_KEY_BYTES],
            client: &mut Connection,
            packet: &[u8],
            out_packet: &mut [u8; NETCODE_MAX_PACKET_SIZE])
                -> Result<Option<ServerEvent>, UpdateError> {
        if packet.len() == 0 {
            return Ok(None)
        }

        trace!("Handling packet from client");

        let decoded = match packet::decode(&packet, protocol_id, Some(&client.client_to_server_key), out_packet) {
            Ok(p) => p,
            Err(e) => {
                info!("Failed to decode packet: {:?}", e);
                client.state = ConnectionState::Disconnected;

                return Ok(Some(ServerEvent::ClientDisconnect(client.client_id)))
            }
        };

        //Update client state with any recieved packet
        let (event, new_state) = match &client.state {
            &ConnectionState::Idle(ref retry) => {
                match decoded {
                    packet::Packet::Payload(len) =>
                        (
                            Some(ServerEvent::Packet(client.client_id, len)),
                            ConnectionState::Idle(retry.update_response(time))
                        ),
                    packet::Packet::KeepAlive(_) => {
                        (None, ConnectionState::Idle(retry.update_response(time)))
                    },
                    packet::Packet::Disconnect => {
                        (Some(ServerEvent::ClientDisconnect(client.client_id)), ConnectionState::Disconnected)
                    },
                    other => {
                        info!("Unexpected packet type {}", other.get_type_id());
                        (None, ConnectionState::Idle(retry.update_response(time)))
                    }
                }
             },
            &ConnectionState::PendingResponse(ref retry) => {
                match decoded {
                    packet::Packet::Response(resp) => {
                        let token = resp.decode(&challenge_key)?;
                        out_packet[..NETCODE_USER_DATA_BYTES].copy_from_slice(&token.user_data);

                        info!("client response");

                        (Some(ServerEvent::ClientConnect(token.client_id)), ConnectionState::Idle(retry.update_response(time)))
                    },
                    p => {
                        info!("Unexpected packet type when waiting for repsonse {}", p.get_type_id());
                        (None, ConnectionState::Idle(retry.update_response(time)))
                    }
                }
            },
            s => (None, s.clone())
        };

        client.state = new_state;

        Ok(event)
    }

    fn find_client_by_id(&self, id: ClientId) -> Option<usize> {
        self.clients.iter().position(|v| v.as_ref().map_or(false, |ref c| c.client_id == id))
    }

    fn find_client_by_addr(&self, addr: &SocketAddr) -> Option<usize> {
        self.clients.iter().position(|v| v.as_ref().map_or(false, |ref c| c.addr == *addr))
    }
}

#[cfg(test)]
mod test {
    use common::*;
    use packet::*;
    use token;
    use super::*;

    use server::socket::capi_simulator::*;

    use std::net::UdpSocket;

    const PROTOCOL_ID: u64 = 0xFFCC;
    const MAX_CLIENTS: usize = 256;
    const CLIENT_ID: u64 = 0xFFEEDD;

    struct TestHarness<I,S> where I: SocketProvider<I,S> {
        next_sequence: u64,
        server: Server<I,S>,
        socket: UdpSocket,
        connect_token: token::ConnectToken
    }

    impl<S,I> TestHarness<I,S> where I: SocketProvider<I,S> {
        pub fn new(port: Option<u16>) -> TestHarness<I,S> {
            let private_key = crypto::generate_key();

            let addr = format!("127.0.0.1:{}", port.unwrap_or(0));
            let mut server = Server::<I,S>::new(&addr, MAX_CLIENTS, PROTOCOL_ID, &private_key).unwrap();
            server.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let socket = UdpSocket::bind(&addr).unwrap();
            socket.connect(server.get_local_addr().unwrap()).unwrap();

            let token = token::ConnectToken::generate(
                                [server.get_local_addr().unwrap()].iter().cloned(),
                                &private_key,
                                30, //Expire
                                0,
                                PROTOCOL_ID,
                                CLIENT_ID, //Client Id
                                None).unwrap();

            TestHarness {
                next_sequence: 0,
                server: server,
                socket: socket,
                connect_token: token
            }
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
            self.socket.send(&data[..len]).unwrap();
        }
        
        fn validate_challenge(&mut self) {
            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            self.server.update(0.0).unwrap();
            self.server.next_event(&mut data).unwrap();
        }

        fn read_challenge(&mut self) -> ChallengePacket {
            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            self.socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let read = self.socket.recv(&mut data).unwrap();

            let mut packet_data = [0; NETCODE_MAX_PACKET_SIZE];
            match packet::decode(&data[..read], PROTOCOL_ID, Some(&self.connect_token.server_to_client_key), &mut packet_data).unwrap() {
                Packet::Challenge(packet) => {
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
            self.socket.send(&data[..len]).unwrap();
        }

        fn validate_response(&mut self) {
            let mut data = [0; NETCODE_MAX_PACKET_SIZE];
            self.server.update(0.0).unwrap();
            let event = self.server.next_event(&mut data);

            match event {
                Ok(Some(ServerEvent::ClientConnect(CLIENT_ID))) => (),
                _ => assert!(false)
            }
        }
    }

    #[allow(dead_code)]
    fn enable_logging() {
        use env_logger::LogBuilder;
        use log::LogLevelFilter;

        LogBuilder::new().filter(None, LogLevelFilter::Trace).init().unwrap();

        use wrapper::private::*;
        unsafe {
            netcode_log_level(NETCODE_LOG_LEVEL_DEBUG as i32);
        }
    }

    #[test]
    fn test_connect() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);
        harness.send_connect_packet();
        harness.validate_challenge();
        let challenge = harness.read_challenge();
        harness.send_response(challenge);
        harness.validate_response();
    }

    #[test]
    fn test_capi_connect() {
        use wrapper::private::*;
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

                harness.server.update(1.0 / 10.0).unwrap();
                loop {
                    let mut data = [0; NETCODE_MAX_PACKET_SIZE];
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

                time += 1.0 / 1.0;
            }

            assert_eq!(netcode_client_state(client), NETCODE_CLIENT_STATE_CONNECTED as i32);

            netcode_client_destroy(client);

            netcode_term();
       }
   }
}
