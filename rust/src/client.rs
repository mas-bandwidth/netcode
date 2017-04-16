use common::*;
use error::*;
use channel::{self, Channel};
use packet;
use socket::SocketProvider;
use token::ConnectToken;

use std::net::SocketAddr;
use std::io;

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

struct RetryState {
    elapsed: f64,
    retry_count: usize
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

pub enum ClientEvent {
    NewState(State),
    SentKeepAlive,
    Packet(usize)
}

pub struct Client<I,S> where I: SocketProvider<I,S> {
    time: f64,
    state: State,
    istate: InternalState,
    channel: Channel,
    socket: I,
    socket_state: S,
    token: ConnectToken
}

impl<I,S> Client<I,S> where I: SocketProvider<I,S> {
    pub fn new(token: &ConnectToken) -> Result<Client<I,S>, io::Error> {
        use std::str::FromStr;

        let mut socket_state = I::new_state();
        let local_addr = SocketAddr::from_str("0.0.0.0:0").unwrap();
        let socket = I::bind(&local_addr, &mut socket_state)?;

        let channel = Channel::new(
            &token.client_to_server_key,
            &token.server_to_client_key,
            &token.hosts.get().next().unwrap(),
            token.protocol,
            0,
            0);

        Ok(Client {
            time: 0.0,
            state: State::SendingConnectionRequest,
            istate: InternalState::Connecting(0, ConnectSequence::SendingToken),
            channel: channel,
            socket: socket,
            socket_state: socket_state,
            token: token.clone()
        })
    }

    pub fn update(&mut self, elapsed: f64) -> Result<(), UpdateError> {
        self.time += elapsed;

        Ok(())
    }

    pub fn next_event(&mut self, payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Option<ClientEvent>, UpdateError> {
        enum Action {
            Disconnect,
            KeepAlive,
            NewHost,
            SendToken(ConnectSequence),
            Payload(usize, SocketAddr),
            Noop
        };

        let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
        let action = match &mut self.istate {
            &mut InternalState::Connecting(mut idx, ref req) => {
                match self.channel.update(self.time, &mut self.socket, false)? {
                    channel::UpdateResult::Expired => {
                        idx += 1;

                        if idx >= self.token.hosts.get().len() {
                            Action::Disconnect
                        } else {
                            Action::NewHost
                        }
                    },
                    channel::UpdateResult::SentKeepAlive => {
                        Action::SendToken(req.clone())
                    },
                    channel::UpdateResult::Noop => Action::Noop
                }
            },
            &mut InternalState::Connected => {
                match self.channel.update(self.time, &mut self.socket, true)? {
                    channel::UpdateResult::Expired => Action::Disconnect,
                    channel::UpdateResult::SentKeepAlive => Action::KeepAlive,
                    channel::UpdateResult::Noop => {
                        match self.socket.recv_from(&mut scratch[..]) {
                            Ok((len, addr)) => Action::Payload(len, addr),
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Action::Noop,
                            Err(e) => return Err(RecvError::SocketError(e).into())
                        }
                    }
                }
            },
            &mut InternalState::Disconnected => Action::Noop
        };

        match action {
            Action::Disconnect => self.disconnect(),
            Action::KeepAlive => Ok(Some(ClientEvent::SentKeepAlive)),
            Action::NewHost => {
                //send initial token, update addr
                Ok(None)
            },
            Action::SendToken(seq) => {
                match seq {
                    ConnectSequence::SendingToken => self.send_connect_token(),
                    ConnectSequence::SendingChallenge(seq, ref token) => self.send_challenge_token(seq, token)
                }
            }
            Action::Payload(len, addr) => {
                self.channel.recv();
                Ok(ClientEvent::Packet(len))
            },
            Action::Noop => Ok(None)
        }
    }

    fn disconnect(&mut self) -> Result<Option<ClientEvent>, UpdateError> {
        self.state = State::Disconnected;
        self.istate = InternalState::Disconnected;

        Ok(Some(ClientEvent::NewState(self.state.clone())))
    }

    fn send_connect_token(&mut self) -> Result<Option<ClientEvent>, UpdateError> {
        let packet = packet::ConnectionRequestPacket::from_token(&self.token);
        
        self.channel.send(self.time, &packet::Packet::ConnectionRequest(packet), None, &mut self.socket)
            .map(|_| None).map_err(|e| e.into())
    }

    fn send_challenge_token(&mut self, sequence: u64, token: &[u8; NETCODE_CHALLENGE_TOKEN_BYTES]) -> Result<Option<ClientEvent>, UpdateError> {
        let packet = packet::ResponsePacket {
            token_sequence: sequence,
            token_data: *token.clone()
        };

        self.channel.send(self.time, &packet::Packet::Response(packet), None, &mut self.socket)
            .map(|_| None).map_err(|e| e.into())
    }

    pub fn send(&mut self, payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<usize, SendError> {
        match self.istate {
            InternalState::Disconnected => return Err(SendError::Disconnected),
            _ => ()
        }

        self.channel.send(self.time, &packet::Packet::Payload(payload.len()), Some(payload), &mut self.socket)
    }
}