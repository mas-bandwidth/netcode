use common::*;
use error::*;
use channel::{self, Channel};
use packet;
use socket::SocketProvider;
use token::ConnectToken;

use std::net::{SocketAddr, UdpSocket};
use std::io;
#[cfg(test)]
use std::time::Duration;

/// States represented by the client
#[derive(Debug,Clone)]
pub enum State {
    /// ConnectToken is expired.
    ConnectTokenExpired,
    /// ConnectToken is invalid.
    InvalidConnectToken,
    /// Connection timed out.
    ConnectionTimedOut,
    /// Connection response timed out.
    ConnectionResponseTimedOut,
    /// Connection request timed out.
    ConnectionRequestTimedOut,
    /// Connection was denied.
    ConnectionDenied,
    /// Client is connected.
    Disconnected,
    /// Sending connection request.
    SendingConnectionRequest,
    /// Sending challenge response.
    SendingConnectionResponse,
    /// Client is connected
    Connected
}

enum InternalState {
    Connecting(usize, ConnectSequence),
    Connected,
    Disconnected
}

enum ConnectSequence {
    SendingToken,
    SendingChallenge(u64, [u8; NETCODE_CHALLENGE_TOKEN_BYTES])
}

impl Clone for ConnectSequence {
    fn clone(&self) -> ConnectSequence {
        match self {
            &ConnectSequence::SendingToken => ConnectSequence::SendingToken,
            &ConnectSequence::SendingChallenge(seq, ref token) => ConnectSequence::SendingChallenge(seq, *token.clone())
        }
    }
}

/// Describes event the server receives when calling `next_event(..)`.
#[derive(Clone, Debug)]
pub enum ClientEvent {
    /// Client state has changed to `State`.
    NewState(State),
    /// Channel is idle and client has sent keep alive packet.
    SentKeepAlive,
    /// Client received packet of `usize` length, packet data is stored in `payload`.
    Packet(usize)
}

/// Netcode client object.
pub struct Client<I,S> where I: SocketProvider<I,S> {
    state: InternalState,
    data: ClientData<I,S>
}

struct ClientData<I,S> where I: SocketProvider<I,S> {
    time: f64,
    ext_state: State,
    channel: Channel,
    socket: I,
    #[allow(dead_code)]
    socket_state: S,
    token: ConnectToken
}

/// UDP based netcode client.
pub type UdpClient = Client<UdpSocket, ()>;

impl<I,S> ClientData<I,S> where I: SocketProvider<I,S> {
    fn disconnect(&mut self, new_state: &mut Option<InternalState>) -> Result<Option<ClientEvent>, UpdateError> {
        self.ext_state = State::Disconnected;
        *new_state = Some(InternalState::Disconnected);

        Ok(Some(ClientEvent::NewState(self.ext_state.clone())))
    }

    fn update_channel(&mut self, send_keep_alive: bool) -> Result<channel::UpdateResult, UpdateError> {
        self.channel.update(self.time, &mut self.socket, send_keep_alive).map_err(|e| e.into())
    }

    fn connect_channel(&mut self, idx: usize) {
        match self.token.hosts.get().skip(idx).next() {
            Some(ref addr) => {
                trace!("Created new channel to {:?}", addr);
                self.channel = Channel::new(
                                &self.token.client_to_server_key,
                                &self.token.server_to_client_key,
                                addr,
                                self.token.protocol,
                                0,
                                0)
            },
            None => ()
        }
    }

    fn begin_host_connect(&mut self, idx: usize) -> Result<Option<ClientEvent>, SendError> {
        self.connect_channel(idx);
        self.send_connect_token()?;
        self.ext_state = State::SendingConnectionRequest;

        Ok(Some(ClientEvent::NewState(self.ext_state.clone())))
    }

    fn handle_payload(&mut self, packet: &packet::Packet, new_state: &mut Option<InternalState>) -> Result<Option<ClientEvent>, UpdateError> {
        match packet {
            &packet::Packet::Payload(len) => {
                Ok(Some(ClientEvent::Packet(len)))
            }
            &packet::Packet::Disconnect => {
                *new_state = Some(InternalState::Disconnected);
                self.ext_state = State::Disconnected;

                Ok(Some(ClientEvent::NewState(self.ext_state.clone())))
            },
            p => {
                trace!("Unexpected packet type {}", p.get_type_id());
                Ok(None)
            }
        }
    }

    fn handle_response(&mut self, packet: &packet::Packet, state: &ConnectSequence, new_state: &mut Option<InternalState>, idx: usize) -> Result<Option<ClientEvent>, UpdateError> {
        match packet {
            &packet::Packet::Challenge(ref challenge) => match state {
                &ConnectSequence::SendingToken => {
                    trace!("Got challenge token, moving to response");

                    *new_state = Some(InternalState::Connecting(idx, ConnectSequence::SendingChallenge(challenge.token_sequence, challenge.token_data)));
                    self.ext_state = State::SendingConnectionResponse;
                    self.send_challenge_token(challenge.token_sequence, &challenge.token_data)?;

                    Ok(Some(ClientEvent::NewState(self.ext_state.clone())))
                }
                &ConnectSequence::SendingChallenge(_,_) => {
                    trace!("Got Challenge token when sending challenge, ignoring");
                    Ok(None)
                }
            },
            &packet::Packet::KeepAlive(_) => match state {
                &ConnectSequence::SendingToken => {
                    trace!("Got keep-alive while sending token, ignoring");
                    Ok(None)
                }
                &ConnectSequence::SendingChallenge(_,_) => {
                    trace!("Got keep-alive while sending challenge, connection established");
                    *new_state = Some(InternalState::Connected);
                    self.ext_state = State::Connected;

                    Ok(Some(ClientEvent::NewState(self.ext_state.clone())))
                }
            },
            p => {
                trace!("Unexpected packet type {}, ignoring", p.get_type_id());
                Ok(None)
            }
        }
    }

    fn send_connect_token(&mut self) -> Result<usize, SendError> {
        let packet = packet::ConnectionRequestPacket::from_token(&self.token);
        
        self.channel.send(self.time, &packet::Packet::ConnectionRequest(packet), None, &mut self.socket)
    }

    fn send_challenge_token(&mut self, sequence: u64, token: &[u8; NETCODE_CHALLENGE_TOKEN_BYTES]) -> Result<usize, SendError> {
        let packet = packet::ResponsePacket {
            token_sequence: sequence,
            token_data: *token.clone()
        };

        self.channel.send(self.time, &packet::Packet::Response(packet), None, &mut self.socket)
    }
}

impl<I,S> Client<I,S> where I: SocketProvider<I,S> {
    /// Constructs a new client from an existing `ConnectToken`.
    pub fn new(token: &ConnectToken) -> Result<Client<I,S>, SendError> {
        Self::new_with_state(token, I::new_state())
    }

    fn new_with_state(token: &ConnectToken, mut socket_state: S) -> Result<Client<I,S>, SendError> {
        use std::str::FromStr;

        let local_addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
        let socket = I::bind(&local_addr, &mut socket_state)?;

        trace!("Client created on socket {:?}", socket.local_addr().unwrap());

        let channel = Channel::new(
            &token.client_to_server_key,
            &token.server_to_client_key,
            &token.hosts.get().next().unwrap(),
            token.protocol,
            0,
            0);

        let mut data = ClientData {
                time: 0.0,
                ext_state: State::SendingConnectionRequest,
                channel: channel,
                socket: socket,
                socket_state: socket_state,
                token: token.clone()
            };

        data.begin_host_connect(0)?;

        Ok(Client {
            state: InternalState::Connecting(0, ConnectSequence::SendingToken),
            data: data
        })
    }

    /// Updates time elapsed since last client iteration.
    pub fn update(&mut self, elapsed: f64) -> Result<(), UpdateError> {
        self.data.time += elapsed;

        Ok(())
    }

    /// Checks for incoming packets and state changes. Returns `None` when no more events
    /// are pending.
    pub fn next_event(&mut self, payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Option<ClientEvent>, UpdateError> {
        let mut new_state = None;

        let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
        let socket_result = match self.data.socket.recv_from(&mut scratch[..]) {
            Ok((len, addr)) => {
                if addr == *self.data.channel.get_addr() {
                    self.data.channel.recv(self.data.time, &scratch[..len], payload).map(|p| Some(p))?
                } else {
                    trace!("Discarded packet from unknown host {:?}", addr);
                    None
                }
            },
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => None,
            Err(e) => return Err(RecvError::SocketError(e).into())
        };

        //If we have any socket data process that first
        let socket_process = if let Some(packet) = socket_result {
            match &mut self.state {
                &mut InternalState::Connecting(idx, ref req) => self.data.handle_response(&packet, req, &mut new_state, idx),
                &mut InternalState::Connected => self.data.handle_payload(&packet, &mut new_state),
                &mut InternalState::Disconnected => Ok(None)
            }
        } else {
            Ok(None)
        };

        let result = match socket_process {
            //If we didn't get a packet, see if there's some upkeep to do
            Ok(None) => {
                match &mut self.state {
                    &mut InternalState::Connecting(mut idx, ref req) => {
                            match self.data.update_channel(false)? {
                                channel::UpdateResult::Expired => {
                                    idx += 1;

                                    if idx >= self.data.token.hosts.get().len() {
                                        info!("Failed to connect to last host, disconnecting");
                                        self.data.disconnect(&mut new_state)
                                    } else {
                                        trace!("Failed to connect to host {:?}, moving to next host", self.data.channel.get_addr());

                                        self.data.begin_host_connect(idx)
                                            .map_err(|e| e.into())
                                    }
                                },
                                channel::UpdateResult::SentKeepAlive => {
                                    let send = match req {
                                        &ConnectSequence::SendingToken => self.data.send_connect_token(),
                                        &ConnectSequence::SendingChallenge(seq, ref token) => self.data.send_challenge_token(seq, token)
                                    };

                                    send.map(|_| None).map_err(|e| e.into())
                                },
                                channel::UpdateResult::Noop => Ok(None)
                            }
                    },
                    &mut InternalState::Connected => {
                        match self.data.update_channel(true)? {
                            channel::UpdateResult::Expired => self.data.disconnect(&mut new_state),
                            channel::UpdateResult::SentKeepAlive => Ok(Some(ClientEvent::SentKeepAlive)),
                            channel::UpdateResult::Noop => Ok(None)
                        }
                    },
                    &mut InternalState::Disconnected => Ok(None)
                }
            },
            r => r
        };

        if let Some(state) = new_state {
            self.state = state;
        }

        result
    }

    /// Sends a packet to connected server.
    pub fn send(&mut self, payload: &[u8]) -> Result<usize, SendError> {
        match payload.len() {
            0 | NETCODE_MAX_PAYLOAD_SIZE => return Err(SendError::PacketSize),
            _ => ()
        }

        match self.state {
            InternalState::Disconnected => return Err(SendError::Disconnected),
            _ => ()
        }

        self.data.channel.send(self.data.time, &packet::Packet::Payload(payload.len()), Some(payload), &mut self.data.socket)
    }

    /// Gets the current state of our client.
    pub fn get_state(&self) -> State {
        self.data.ext_state.clone()
    }

    #[cfg(test)]
    fn set_read_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error> {
        self.data.socket.set_recv_timeout(duration)
    }
    
    #[cfg(test)]
    pub fn get_socket_state(&mut self) -> &mut S {
        &mut self.data.socket_state
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use server::*;
    use token;
    use crypto;
    use std::time::Duration;

    const PROTOCOL_ID: u64 = 0xFFCC;
    const MAX_CLIENTS: usize = 256;
    const CLIENT_ID: u64 = 0xFFEEDD;

    struct TestHarness<I,S> where I: SocketProvider<I,S> {
        client: Client<I,S>,
        server: Option<Server<I,S>>
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

    impl<S,I> TestHarness<I,S> where I: SocketProvider<I,S>, S: Clone {
        pub fn new(in_token: Option<ConnectToken>) -> TestHarness<I,S> {
            let private_key = crypto::generate_key();

            let addr = format!("127.0.0.1:0");
            let (server, mut client) = if let Some(ref token) = in_token {
                let client = Client::<I,S>::new_with_state(token, I::new_state()).unwrap();
                (None, client)
            } else {
                let mut server = Server::<I,S>::new(&addr, MAX_CLIENTS, PROTOCOL_ID, &private_key).unwrap();
                server.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                let token = Self::generate_connect_token(&private_key, server.get_local_addr().unwrap());
                let client = Client::<I,S>::new_with_state(&token, server.get_socket_state().clone()).unwrap();
                (Some(server), client)
            };

            client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

            TestHarness {
                server: server,
                client: client
            }
        }


        pub fn generate_connect_token(private_key: &[u8; NETCODE_KEY_BYTES], addr: SocketAddr) -> token::ConnectToken {
            token::ConnectToken::generate(
                                [addr].iter().cloned(),
                                private_key,
                                30, //Expire
                                0,
                                PROTOCOL_ID,
                                CLIENT_ID, //Client Id
                                None).unwrap()
        }

        pub fn update_client(&mut self) -> Option<ClientEvent> {
            let mut scratch = [0; NETCODE_MAX_PAYLOAD_SIZE];
            self.client.update(0.0).unwrap();
            self.client.next_event(&mut scratch).unwrap()
        }

        pub fn update_server(&mut self) -> Option<ServerEvent> {
            if let Some(ref mut server) = self.server {
                let mut scratch = [0; NETCODE_MAX_PAYLOAD_SIZE];
                server.update(0.0).unwrap();
                server.next_event(&mut scratch).unwrap()
            } else {
                None
            }
        }
    }
 
    #[test]
    fn test_client_connect() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);

        match harness.client.get_state() {
            State::SendingConnectionRequest => (),
            _ => assert!(false)
        }

        harness.update_server();
        match harness.update_client().unwrap() {
            ClientEvent::NewState(State::SendingConnectionResponse) => (),
            s => assert!(false, "{:?}", s)
        }
        
        harness.update_server();
        match harness.update_client().unwrap() {
            ClientEvent::NewState(State::Connected) => (),
            s => assert!(false, "{:?}", s)
        }
    }

    #[test]
    fn test_payload() {
        let mut harness = TestHarness::<UdpSocket,()>::new(None);

        //Pending response
        harness.update_server();
        harness.update_client().unwrap();
        
        //Connected
        harness.update_server();
        match harness.update_client().unwrap() {
            ClientEvent::NewState(State::Connected) => (),
            s => assert!(false, "{:?}", s)
        }
   
        for i in 1..NETCODE_MAX_PAYLOAD_SIZE {
            let mut data = [0; NETCODE_MAX_PAYLOAD_SIZE];
            for d in 0..i {
                data[d] = d as u8;
            }

            harness.client.send(&data[..i]).unwrap();
            if let Some(server) = harness.server.as_mut() {
                {
                    server.update(0.0).unwrap();
                    let mut payload = [0; NETCODE_MAX_PAYLOAD_SIZE];
                    match server.next_event(&mut payload) {
                        Ok(Some(ServerEvent::Packet(client_id, len))) => {
                            assert_eq!(len, i);
                            assert_eq!(client_id, CLIENT_ID);
                            for d in 0..i {
                                assert_eq!(payload[d], data[d]);
                            }
                        },
                        Ok(e) => assert!(false, "{:?}", e),
                        Err(e) => assert!(false, "{:?}", e)
                    }
                }

                {
                    server.send(CLIENT_ID, &data[..i]).unwrap();
                    harness.client.update(0.0).unwrap();
                    let mut payload = [0; NETCODE_MAX_PAYLOAD_SIZE];
                    match harness.client.next_event(&mut payload) {
                        Ok(Some(ClientEvent::Packet(len))) => {
                            assert_eq!(len, i);
                            for d in 0..i {
                                assert_eq!(payload[d], data[d]);
                            }
                        },
                        Ok(e) => assert!(false, "{:?}", e),
                        Err(e) => assert!(false, "{:?}", e)
                    }
                }
            } else {
                assert!(false);
            }

        }
    }
}