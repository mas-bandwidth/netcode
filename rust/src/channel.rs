use common::*;
use error::*;
use replay::ReplayProtection;
use packet::{self, Packet, KeepAlivePacket};
use socket::SocketProvider;

use std::net::SocketAddr;

pub const TIMEOUT_SECONDS: u32 = 5;
pub const KEEPALIVE_RETRY: f64 = 1.0 / 10.0;

#[derive(Clone, Debug)]
pub struct KeepAliveState {
    pub last_sent: f64,
    pub last_response: f64
}

impl KeepAliveState {
    pub fn new() -> KeepAliveState {
        KeepAliveState {
            last_sent: 0.0,
            last_response: 0.0
        }
    }

    pub fn update_sent(&self, time: f64) -> KeepAliveState {
        KeepAliveState {
            last_sent: time,
            last_response: self.last_response
        }
    }

    pub fn update_response(&self, response: f64) -> KeepAliveState {
        KeepAliveState {
            last_sent: self.last_sent,
            last_response: response
        }
    }

    pub fn has_expired(&self, time: f64) -> bool {
        self.last_response + (TIMEOUT_SECONDS as f64) < time
    }

    pub fn should_send_keepalive(&self, time: f64) -> bool {
        self.last_sent + KEEPALIVE_RETRY < time
    }
}

#[derive(Clone)]
pub struct Channel {
    keep_alive: KeepAliveState,
    send_key: [u8; NETCODE_KEY_BYTES],
    recv_key: [u8; NETCODE_KEY_BYTES],
    replay_protection: ReplayProtection,
    next_sequence: u64,
    addr: SocketAddr,
    protocol_id: u64,
    client_idx: usize,
    max_clients: usize
}

pub enum UpdateResult {
    Noop,
    SentKeepAlive,
    Expired
}

impl Channel {
    pub fn new(send_key: &[u8; NETCODE_KEY_BYTES],
               recv_key: &[u8; NETCODE_KEY_BYTES],
               addr: &SocketAddr,
               protocol_id: u64,
               client_idx: usize,
               max_clients: usize) -> Channel {
        Channel {
            keep_alive: KeepAliveState::new(),
            send_key: send_key.clone(),
            recv_key: recv_key.clone(),
            replay_protection: ReplayProtection::new(),
            next_sequence: 0,
            addr: addr.clone(),
            protocol_id: protocol_id,
            client_idx: client_idx,
            max_clients: max_clients
        }
    }

    pub fn send<I,S>(&mut self, elapsed: f64, packet: &Packet, payload: Option<&[u8]>, socket: &mut I) -> Result<usize, SendError> where I: SocketProvider<I,S> {
        let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
        let len = packet::encode(&mut scratch, self.protocol_id, packet, Some((self.next_sequence, &self.send_key)), payload)?;

        socket.send_to(&scratch[..len], &self.addr)?;

        self.next_sequence += 1;
        self.keep_alive.update_sent(elapsed);

        Ok(len)
    }

    pub fn recv(&mut self, elapsed: f64, packet: &[u8], out_payload: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE]) -> Result<Packet, RecvError> {
        let (seq, packet) = packet::decode(packet, self.protocol_id, Some(&self.recv_key), out_payload)?;

        if self.replay_protection.packet_already_received(seq) {
            return Err(RecvError::DuplicateSequence)
        }

        self.keep_alive.update_response(elapsed);

        Ok(packet)
    }

    pub fn update<I,S>(&mut self, elapsed: f64, socket: &mut I, send_keep_alive: bool) -> Result<UpdateResult, SendError> where I: SocketProvider<I,S> {
        if self.keep_alive.should_send_keepalive(elapsed) {
            let keep_alive = KeepAlivePacket {
                client_idx: self.client_idx as i32,
                max_clients: self.max_clients as i32
            };

            if send_keep_alive {
                self.send(elapsed, &Packet::KeepAlive(keep_alive), None, socket)?;
            }

            return Ok(UpdateResult::SentKeepAlive)
        }

        if self.keep_alive.has_expired(elapsed) {
            return Ok(UpdateResult::Expired)
        }

        Ok(UpdateResult::Noop)
    }

    pub fn get_addr(&self) -> &SocketAddr {
        &self.addr
    }
}