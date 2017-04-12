use std::net::SocketAddr;

use common::*;
use server;

/// Current state of the client connection.
#[derive(Clone, Debug)]
pub enum ConnectionState {
    /// We've recieved the initial packet but response is outstanding yet.
    PendingResponse(RetryState),
    /// Connection is idle and waiting to send heartbeat.
    Idle(RetryState),
    /// Client timed out from heartbeat packets.
    TimedOut,
    /// Client has cleanly disconnected.
    Disconnected
}

#[derive(Clone, Debug)]
pub struct RetryState {
    pub last_sent: f64,
    pub last_response: f64
}

impl RetryState {
    pub fn update_sent(&self, sent: f64) -> RetryState {
        RetryState {
            last_sent: sent,
            last_response: self.last_response
        }
    }

    pub fn update_response(&self, response: f64) -> RetryState {
        RetryState {
            last_sent: self.last_sent,
            last_response: response
        }
    }

    pub fn has_expired(&self, time: f64) -> bool {
        self.last_response + (NETCODE_TIMEOUT_SECONDS as f64) < time
    }

    pub fn should_send_keepalive(&self, time: f64) -> bool {
        self.last_sent + NETCODE_KEEPALIVE_RETRY < time
    }
}

/// Handle to client connection.
#[derive(Clone)]
pub struct Connection {
    pub client_id: server::ClientId,
    pub state: ConnectionState,
    pub server_to_client_key: [u8; NETCODE_KEY_BYTES],
    pub client_to_server_key: [u8; NETCODE_KEY_BYTES],
    pub addr: SocketAddr
}
