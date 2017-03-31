use std::net::SocketAddr;

use server;

/// Current state of the client connection.
#[derive(Clone)]
pub enum ConnectionState {
    /// We've recieved the initial packet but response is outstanding yet.
    PendingResponse(RetryState),
    /// Handshake is complete and client is connected.
    Connected,
    /// Connection is idle and waiting to send heartbeat.
    Idle(RetryState),
    /// Client timed out from heartbeat packets.
    TimedOut,
    /// Client has cleanly disconnected.
    Disconnected
}

#[derive(Clone)]
pub struct RetryState {
    pub last_update: f64,
    pub last_retry: f64,
    pub retry_count: usize
}

impl RetryState {
    pub fn new(time: f64) -> RetryState {
        RetryState {
            last_update: time,
            last_retry: 0.0,
            retry_count: 0
        }
    }
}

/// Handle to client connection.
#[derive(Clone)]
pub struct Connection {
    pub client_id: server::ClientId,
    pub state: ConnectionState,
    pub addr: SocketAddr
}
