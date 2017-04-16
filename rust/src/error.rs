use std::io;

use packet;

/// Errors from updating server.
#[derive(Debug)]
pub enum UpdateError {
    /// Packet buffer was too small to recieve the largest packet(`NETCODE_MAX_PAYLOAD_LEN` = 1775)
    PacketBufferTooSmall,
    /// An error happened when receiving a packet.
    RecvError(RecvError),
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

/// Errors from sending packets
#[derive(Debug)]
pub enum SendError {
    /// Client Id used for sending didn't exist.
    InvalidClientId,
    /// Failed to encode the packet for sending.
    PacketEncodeError(packet::PacketError),
    /// Packet is larger than [PACKET_MAX_PAYLOAD_SIZE](constant.NETCODE_MAX_PAYLOAD_SIZE.html) or equals zero.
    PacketSize,
    /// Generic io error.
    SocketError(io::Error)
}

/// Errors from receiving packets
#[derive(Debug)]
pub enum RecvError {
    /// Failed to decode packet.
    PacketDecodeError(packet::PacketError),
    /// We've already received this packet before.
    DuplicateSequence,
    /// IO error occured on the socket.
    SocketError(io::Error)
}

impl From<packet::PacketError> for RecvError {
    fn from(err: packet::PacketError) -> RecvError {
        RecvError::PacketDecodeError(err)
    }
}

impl From<RecvError> for UpdateError {
    fn from(err: RecvError) -> UpdateError {
        UpdateError::RecvError(err)
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

impl From<io::Error> for RecvError {
    fn from(err: io::Error) -> RecvError {
        RecvError::SocketError(err)
    }
}