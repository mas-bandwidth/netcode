use std::net::SocketAddr;

/// Current state of the client connection.
#[derive(Clone)]
pub enum ConnectionState {
    /// We've recieved the initial packet but response is outstanding yet.
    PendingResponse(f64),
    /// Handshake is complete and client is connected.
    Connected,
    /// Connection is idle and waiting to send heartbeat.
    Idle(f64),
    /// Client timed out from heartbeat packets.
    TimedOut,
    /// Client has cleanly disconnected.
    Disconnected
}

/// Handle to client connection.
#[derive(Clone)]
pub struct Connection {
    pub state: ConnectionState,
    pub addr: SocketAddr
}
