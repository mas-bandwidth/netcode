use std::io;
use std::io::{Read, Write};
use std::error;
use std::fmt;

use byteorder::{WriteBytesExt, ReadBytesExt, BigEndian};

use common::*;
use crypto;

const PACKET_CONNECTION: u8 = 0;
const PACKET_CONNECTION_DENIED: u8 = 1;
const PACKET_CHALLENGE: u8 = 2;
const PACKET_RESPONSE: u8 = 3;
const PACKET_KEEPALIVE: u8 = 4;
const PACKET_PAYLOAD: u8 = 5;
const PACKET_DISCONNECT: u8 = 6;

pub enum Packet {
    ConnectionRequest(ConnectionRequestPacket),
    ConnectionDenied(ConnectionDeniedPacket),
    Challenge(ChallengePacket),
    Response(ResponsePacket),
    KeepAlive(KeepAlivePacket),
    Payload(usize),
    Disconnect
}

impl Packet {
    fn get_type_id(&self) -> u8 {
        match self {
            &Packet::ConnectionRequest(_) => PACKET_CONNECTION,
            &Packet::ConnectionDenied(_) => PACKET_CONNECTION_DENIED,
            &Packet::Challenge(_) => PACKET_CHALLENGE,
            &Packet::Response(_) => PACKET_RESPONSE,
            &Packet::KeepAlive(_) => PACKET_KEEPALIVE,
            &Packet::Payload(_) => PACKET_PAYLOAD,
            &Packet::Disconnect => PACKET_DISCONNECT
        }
    }

    fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        match self {
            &Packet::ConnectionRequest(ref p) => p.write(out),
            &Packet::ConnectionDenied(ref p) => p.write(out),
            &Packet::Challenge(ref p) => p.write(out),
            &Packet::Response(ref p) => p.write(out),
            &Packet::KeepAlive(ref p) => p.write(out),
            &Packet::Payload(_) | &Packet::Disconnect => Ok(())
        }
    }
}

fn decode_prefix(value: u8) -> (u8, usize) {
    ((value & 0xF) as u8, (value >> 4) as usize)
}

fn encode_prefix(value: u8, sequence: u64) -> u8 {
    value | ((sequence_bytes_required as u8) << 4)
}

fn sequence_bytes_required(sequence: u64) -> usize
{
    let mut mask: u64 = 0xFF00000000000000;
    for i in 0..7 {
        if (sequence & mask) != 0x00 {
            return 8 - i
        }

        mask >>= 8;
    }

    1
}

#[derive(Debug)]
enum PacketError {
    InvalidPrivateKey,
    InvalidPacket,
    DecryptError(crypto::EncryptError),
    GenericIO(io::Error)
}

impl From<io::Error> for PacketError {
    fn from(err: io::Error) -> PacketError {
        PacketError::GenericIO(err)
    }
}

impl From<crypto::EncryptError> for PacketError {
    fn from(err: crypto::EncryptError) -> PacketError {
        PacketError::DecryptError(err)
    }
}

fn write_sequence<W>(out: &mut W, seq: u64) -> Result<usize, io::Error> where W: io::Write {
    let len = sequence_bytes_required(seq);

    let mut sequence_scratch = [0; 8];
    io::Cursor::new(&mut sequence_scratch[..]).write_u64::<BigEndian>(seq)?;

    out.write(&sequence_scratch[8-len..8])
}

fn read_sequence<R>(source: &mut R, len: usize) -> Result<u64, io::Error> where R: io::Read {
    let mut seq_scratch = [0; 8];
    source.read_exact(&mut seq_scratch[8-len..8])?;
    io::Cursor::new(&seq_scratch).read_u64::<BigEndian>()
}

fn decode(data: &[u8], private_key: Option<&[u8; NETCODE_KEY_BYTES]>, out: &mut [u8; NETCODE_MAX_PACKET_SIZE])
        -> Result<Packet, PacketError> {
    let mut source = &mut io::Cursor::new(data);
    let (ty, sequence_len) = decode_prefix(source.read_u8()?);

    if ty == PACKET_CONNECTION {
        Ok(Packet::ConnectionRequest(ConnectionRequestPacket::read(source)?))
    } else {
        if let Some(private_key) = private_key {
            //Sequence length is variable on the wire so we have to serialize only
            //the number of bytes we were told exist.
            let sequence = read_sequence(source, sequence_len)?;

            let payload = &data[source.position() as usize..];
            let decoded_len = crypto::decode(out, payload, None, sequence, private_key)?;

            let mut source_data = &mut io::Cursor::new(&out[..decoded_len]);

            match ty {
                PACKET_CONNECTION_DENIED => Ok(Packet::ConnectionDenied(ConnectionDeniedPacket::read(source_data)?)),
                PACKET_CHALLENGE => Ok(Packet::Challenge(ChallengePacket::read(source_data)?)),
                PACKET_RESPONSE => Ok(Packet::Response(ResponsePacket::read(source_data)?)),
                PACKET_KEEPALIVE => Ok(Packet::KeepAlive(KeepAlivePacket::read(source_data)?)),
                PACKET_PAYLOAD => {
                    Ok(Packet::Payload(decoded_len))
                },
                PACKET_DISCONNECT => Ok(Packet::Disconnect),
                PACKET_CONNECTION | _ => Err(PacketError::InvalidPacket)
            }
        } else {
            Err(PacketError::InvalidPrivateKey)
        }
    }
}

fn encode(out: &mut [u8], packet: &Packet, private_key: Option<&[u8; NETCODE_KEY_BYTES]>, sequence: u64)
        -> Result<usize, PacketError> {
    let (offset, sequence) = {
        let mut write = &mut io::Cursor::new(&mut out[..]);

        write.write_u8(encode_prefix(packet.get_type_id(), sequence))?;
        write.write_u64::<BigEndian>(sequence)?;

        write_sequence(write, sequence)?;

        (write.position(), sequence)
    };

    if let &Packet::ConnectionRequest(ref req) = packet {
        let mut writer = io::Cursor::new(&mut out[offset as usize..]);
        req.write(&mut writer)?;

        Ok((offset + writer.position()) as usize)
    } else {
        let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
        let scractch_written = {
            let mut scratch_write = io::Cursor::new(&mut scratch[..]);
            packet.write(&mut scratch_write)?;

            scratch_write.position()
        };

        if let Some(private_key) = private_key {
            let crypt_write = crypto::encode(
                &mut out[offset as usize..],
                &scratch[0..scractch_written as usize],
                None,
                sequence,
                private_key)?;

            Ok(offset as usize + crypt_write)
        } else {
            Err(PacketError::InvalidPrivateKey)
        }
    }
}

pub struct ConnectionRequestPacket {
    version: [u8; NETCODE_VERSION_LEN],
    protocol_id: u64,
    token_expire: u64,
    sequence: u64,
    private_data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES]
}

impl ConnectionRequestPacket {
    pub fn read<R>(source: &mut R) -> Result<ConnectionRequestPacket, io::Error> where R: io::Read {
        let mut version = [0; NETCODE_VERSION_LEN];
        source.read_exact(&mut version[..])?;

        let protocol_id = source.read_u64::<BigEndian>()?;
        let token_expire = source.read_u64::<BigEndian>()?;
        let sequence = source.read_u64::<BigEndian>()?;

        let mut private_data = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
        source.read_exact(&mut private_data[..])?;

        Ok(ConnectionRequestPacket {
            version: version,
            protocol_id: protocol_id,
            token_expire: token_expire,
            sequence: sequence,
            private_data: private_data
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write(&self.version)?;
        out.write_u64::<BigEndian>(self.protocol_id)?;
        out.write_u64::<BigEndian>(self.token_expire)?;
        out.write_u64::<BigEndian>(self.sequence)?;
        out.write(&self.private_data)?;

        Ok(())
    }
}

pub struct ConnectionDeniedPacket {
    reason: u32
}

impl ConnectionDeniedPacket {
    pub fn read<R>(source: &mut R) -> Result<ConnectionDeniedPacket, io::Error> where R: io::Read {
        Ok(ConnectionDeniedPacket {
            reason: source.read_u32::<BigEndian>()?
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u32::<BigEndian>(self.reason)?;

        Ok(())
    }
}

pub struct ChallengePacket {
    token_sequence: u64,
    token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES]
}

impl ChallengePacket {
    pub fn read<R>(source: &mut R) -> Result<ChallengePacket, io::Error> where R: io::Read {
        let token_sequence = source.read_u64::<BigEndian>()?;
        let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        source.read_exact(&mut token_data)?;

        Ok(ChallengePacket {
            token_sequence: token_sequence,
            token_data: token_data
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<BigEndian>(self.token_sequence)?;
        out.write(&self.token_data)?;

        Ok(())
    }
}

pub struct ResponsePacket {
    token_sequence: u64,
    token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES]
}

impl ResponsePacket {
    pub fn read<R>(source: &mut R) -> Result<ResponsePacket, io::Error> where R: io::Read {
        let token_sequence = source.read_u64::<BigEndian>()?;
        let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        source.read_exact(&mut token_data)?;

        Ok(ResponsePacket {
            token_sequence: token_sequence,
            token_data: token_data
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<BigEndian>(self.token_sequence)?;
        out.write(&self.token_data)?;

        Ok(())
    }
}

pub struct KeepAlivePacket {
    client_idx: u64
}

impl KeepAlivePacket {
    pub fn read<R>(source: &mut R) -> Result<KeepAlivePacket, io::Error> where R: io::Read {
        Ok(KeepAlivePacket {
            client_idx: source.read_u64::<BigEndian>()?
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<BigEndian>(self.client_idx)?;

        Ok(())
    }
}

#[cfg(test)]
fn test_seq_value(v: u64) {
    let mut scratch = [0; 8];
    write_sequence(&mut io::Cursor::new(&mut scratch[..]), v).unwrap();
    assert_eq!(v, read_sequence(&mut io::Cursor::new(&scratch[..]), sequence_bytes_required(v)).unwrap());
}

#[test]
fn test_sequence() {
    let mut bits = 0xCC;

    for _ in 0..8 {
        test_seq_value(bits);
        bits <<= 8;
    }
}
/*
#[test]
fn test_conn_packet() {
    let protocol_id = 0xFFCC;
    let token_expire = 0xCCFF;
    let sequence = 0xCCDD;
    let mut private_data = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    for i in 0..NETCODE_CONNECT_TOKEN_PRIVATE_BYTES {
        private_data[i] = i as u8;
    }

    let packet = Packet::ConnectionRequest(ConnectionRequestPacket {
        version: NETCODE_VERSION_STRING.clone(),
        protocol_id: protocol_id,
        token_expire: token_expire,
        sequence: sequence,
        private_data: private_data
    });

    let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
    let mut out_packet = [0; NETCODE_MAX_PACKET_SIZE];
    encode(&mut scratch[..], &packet, None, sequence).unwrap();
    match decode(&scratch[..], None, &mut out_packet) {
        Ok(p) => match p {
            Packet::ConnectionRequest(p) => {
                assert_eq!(p.protocol_id, protocol_id);
                assert_eq!(p.token_expire, token_expire);
                assert_eq!(p.sequence, sequence);

                for i in 0..p.version.len() {
                    assert_eq!(p.version[i], NETCODE_VERSION_STRING[i]);
                }

                for i in 0..p.private_data.len() {
                    assert_eq!(p.private_data[i], private_data[i]);
                }
            },
            _ => assert!(false)
        },
        Err(_) => assert!(false)
    }
}
*/