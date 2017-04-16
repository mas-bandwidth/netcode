use server;
use channel::Channel;

/// Current state of the client connection.
#[derive(Clone, Debug)]
pub enum ConnectionState {
    /// We've recieved the initial packet but response is outstanding yet.
    PendingResponse,
    /// Connection is idle and waiting to send heartbeat.
    Idle,
    /// Client timed out from heartbeat packets.
    TimedOut,
    /// Client has cleanly disconnected.
    Disconnected
}

/// Handle to client connection.
#[derive(Clone)]
pub struct Connection {
    pub client_id: server::ClientId,
    pub state: ConnectionState,
    pub channel: Channel
}
