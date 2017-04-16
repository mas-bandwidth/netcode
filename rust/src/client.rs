use common::*;
use error::*;
use packet;
use socket::SocketProvider;
use token::ConnectToken;

use std::net::SocketAddr;
use std::io;

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
    Connected(SocketAddr),
    Disconnected
}

struct RetryState {
    elapsed: f64,
    retry_count: usize
}

enum ConnectSequence {
    SendingToken(RetryState),
    SendingChallenge(RetryState, packet::ChallengeToken),
    PendingKeepAlive
}

pub enum ClientEvent {
    NewState(State),
    Packet(usize)
}

pub struct Client<I,S> where I: SocketProvider<I,S> {
    state: State,
    istate: InternalState,
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

        Ok(Client {
            state: State::SendingConnectionRequest,
            istate: InternalState::Connecting(0, ConnectSequence::SendingToken(RetryState { elapsed: 0.0, retry_count: 0 })),
            socket: socket,
            socket_state: socket_state,
            token: token.clone()
        })
    }

    pub fn next_event(&mut self, payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Option<ClientEvent>, UpdateError> {
        Ok(None)
    }

    pub fn send(&mut self, payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<usize, SendError> {
        Ok(0)
    }
}