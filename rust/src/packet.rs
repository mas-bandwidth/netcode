use std::io;
use std::io::Write;

use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian};

use common::*;
use crypto;
use token;

const PACKET_CONNECTION: u8 = 0;
const PACKET_CONNECTION_DENIED: u8 = 1;
const PACKET_CHALLENGE: u8 = 2;
const PACKET_RESPONSE: u8 = 3;
const PACKET_KEEPALIVE: u8 = 4;
const PACKET_PAYLOAD: u8 = 5;
const PACKET_DISCONNECT: u8 = 6;

pub enum Packet {
    ConnectionRequest(ConnectionRequestPacket),
    ConnectionDenied,
    Challenge(ChallengePacket),
    Response(ResponsePacket),
    KeepAlive(KeepAlivePacket),
    Payload(usize),
    Disconnect
}

impl Packet {
    pub fn get_type_id(&self) -> u8 {
        match self {
            &Packet::ConnectionRequest(_) => PACKET_CONNECTION,
            &Packet::ConnectionDenied => PACKET_CONNECTION_DENIED,
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
            &Packet::ConnectionDenied => Ok(()),
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
    value | ((sequence_bytes_required(sequence) as u8) << 4)
}

fn sequence_bytes_required(sequence: u64) -> usize
{
    let mut mask: u64 = 0xFF00000000000000;
    for i in 0..8 {
        if (sequence & mask) != 0x00 {
            return 8 - i
        }

        mask >>= 8;
    }

    0
}

#[derive(Debug)]
pub enum PacketError {
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
    io::Cursor::new(&mut sequence_scratch[..]).write_u64::<LittleEndian>(seq)?;

    out.write(&sequence_scratch[0..len])
}

fn read_sequence<R>(source: &mut R, len: usize) -> Result<u64, io::Error> where R: io::Read {
    let mut seq_scratch = [0; 8];
    source.read_exact(&mut seq_scratch[0..len])?;
    io::Cursor::new(&seq_scratch).read_u64::<LittleEndian>()
}

fn get_additional_data(prefix: u8, protocol_id: u64) -> Result<[u8; NETCODE_VERSION_LEN + 8 + 1], io::Error> {
    let mut buffer = [0; NETCODE_VERSION_LEN + 8 + 1];

    {
        let mut writer = io::Cursor::new(&mut buffer[..]);

        writer.write(&NETCODE_VERSION_STRING[..])?;
        writer.write_u64::<LittleEndian>(protocol_id)?;
        writer.write_u8(prefix)?;
    }

    Ok(buffer)
}

pub fn decode(data: &[u8], protocol_id: u64, private_key: Option<&[u8; NETCODE_KEY_BYTES]>, out: &mut [u8; NETCODE_MAX_PAYLOAD_SIZE])
        -> Result<(u64, Packet), PacketError> {
    let mut source = &mut io::Cursor::new(data);
    let prefix_byte = source.read_u8()?;
    let (ty, sequence_len) = decode_prefix(prefix_byte);

    if ty == PACKET_CONNECTION {
        Ok((0, Packet::ConnectionRequest(ConnectionRequestPacket::read(source)?)))
    } else {
        if let Some(private_key) = private_key {
            //Sequence length is variable on the wire so we have to serialize only
            //the number of bytes we were told exist.
            let sequence = read_sequence(source, sequence_len)?;

            let payload = &data[source.position() as usize..];
            let additional_data = get_additional_data(prefix_byte, protocol_id)?;

            let decoded_len = crypto::decode(out, payload, Some(&additional_data[..]), sequence, private_key)?;

            let mut source_data = &mut io::Cursor::new(&out[..decoded_len]);

            let packet = match ty {
                PACKET_CONNECTION_DENIED => Ok(Packet::ConnectionDenied),
                PACKET_CHALLENGE => Ok(Packet::Challenge(ChallengePacket::read(source_data)?)),
                PACKET_RESPONSE => Ok(Packet::Response(ResponsePacket::read(source_data)?)),
                PACKET_KEEPALIVE => Ok(Packet::KeepAlive(KeepAlivePacket::read(source_data)?)),
                PACKET_PAYLOAD => {
                    Ok(Packet::Payload(decoded_len))
                },
                PACKET_DISCONNECT => Ok(Packet::Disconnect),
                PACKET_CONNECTION | _ => Err(PacketError::InvalidPacket)
            };

            packet.map(|p| (sequence, p))
        } else {
            Err(PacketError::InvalidPrivateKey)
        }
    }
}

pub fn encode(out: &mut [u8], protocol_id: u64, packet: &Packet, crypt_info: Option<(u64, &[u8; NETCODE_KEY_BYTES])>, payload: Option<&[u8]>)
        -> Result<usize, PacketError> {
    if let &Packet::ConnectionRequest(ref req) = packet {
        let mut writer = io::Cursor::new(&mut out[..]);

        //First byte is always id + sequence
        writer.write_u8(encode_prefix(packet.get_type_id(), 0))?;
        req.write(&mut writer)?;

        Ok(writer.position() as usize)
    } else {
        if let Some((sequence, private_key)) = crypt_info {
            let (prefix_byte, offset) = {
                let mut write = &mut io::Cursor::new(&mut out[..]);

                //First byte is always id + sequence
                let prefix_byte = encode_prefix(packet.get_type_id(), sequence);
                write.write_u8(prefix_byte)?;
                write_sequence(write, sequence)?;

                (prefix_byte, write.position())
            };

            let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
            let scratch_written = {
                let mut scratch_write = io::Cursor::new(&mut scratch[..]);
                packet.write(&mut scratch_write)?;

                if let Some(payload) = payload {
                    scratch_write.write(payload)?;
                }

                scratch_write.position()
            };

            let additional_data = get_additional_data(prefix_byte, protocol_id)?;

            let crypt_write = crypto::encode(
                &mut out[offset as usize..],
                &scratch[..scratch_written as usize],
                Some(&additional_data[..]),
                sequence,
                private_key)?;

            Ok(offset as usize + crypt_write)
        } else {
            Err(PacketError::InvalidPrivateKey)
        }
    }
}

pub struct ConnectionRequestPacket {
    pub version: [u8; NETCODE_VERSION_LEN],
    pub protocol_id: u64,
    pub token_expire: u64,
    pub sequence: u64,
    pub private_data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES]
}

impl ConnectionRequestPacket {
    pub fn from_token(token: &token::ConnectToken) -> ConnectionRequestPacket {
        ConnectionRequestPacket {
            version: NETCODE_VERSION_STRING.clone(),
            protocol_id: token.protocol,
            token_expire: token.expire_utc,
            sequence: token.sequence,
            private_data: token.private_data
        }
    }

    pub fn read<R>(source: &mut R) -> Result<ConnectionRequestPacket, io::Error> where R: io::Read {
        let mut version = [0; NETCODE_VERSION_LEN];
        source.read_exact(&mut version[..])?;

        let protocol_id = source.read_u64::<LittleEndian>()?;
        let token_expire = source.read_u64::<LittleEndian>()?;
        let sequence = source.read_u64::<LittleEndian>()?;

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
        out.write_u64::<LittleEndian>(self.protocol_id)?;
        out.write_u64::<LittleEndian>(self.token_expire)?;
        out.write_u64::<LittleEndian>(self.sequence)?;
        out.write(&self.private_data)?;

        Ok(())
    }
}

pub struct ChallengeToken {
    pub client_id: u64,
    pub user_data: [u8; NETCODE_USER_DATA_BYTES]
}

impl Clone for ChallengeToken {
    fn clone(&self) -> ChallengeToken {
        ChallengeToken {
            client_id: self.client_id,
            user_data: self.user_data
        }
    }
}

impl ChallengeToken {
    pub fn generate(client_id: u64,
            connect_user_data: &[u8; NETCODE_USER_DATA_BYTES])
                -> ChallengeToken {

        let mut user_data = [0; NETCODE_USER_DATA_BYTES];
        user_data.copy_from_slice(connect_user_data);

        ChallengeToken {
            client_id: client_id,
            user_data: user_data
        }
    }

    pub fn read<R>(source: &mut R) -> Result<ChallengeToken, io::Error> where R: io::Read {
        let client_id = source.read_u64::<LittleEndian>()?;
        let mut user_data = [0; NETCODE_USER_DATA_BYTES];
        source.read_exact(&mut user_data)?;

        Ok(ChallengeToken {
            client_id: client_id,
            user_data: user_data
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<LittleEndian>(self.client_id)?;
        out.write(&self.user_data)?;

        Ok(())
    }
}

pub struct ChallengePacket {
    pub token_sequence: u64,
    pub token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES]
}

#[derive(Debug)]
pub enum ChallengeEncodeError {
    Io(io::Error),
    Encrypt(crypto::EncryptError)
}

impl From<io::Error> for ChallengeEncodeError {
    fn from(err: io::Error) -> ChallengeEncodeError {
        ChallengeEncodeError::Io(err)
    }
}

impl From<crypto::EncryptError> for ChallengeEncodeError {
    fn from(err: crypto::EncryptError) -> ChallengeEncodeError {
        ChallengeEncodeError::Encrypt(err)
    }
}

impl ChallengePacket {
    pub fn generate(client_id: u64,
            connect_user_data: &[u8; NETCODE_USER_DATA_BYTES],
            challenge_sequence: u64,
            challenge_key: &[u8; NETCODE_KEY_BYTES])
            -> Result<ChallengePacket, ChallengeEncodeError> {
        let token = ChallengeToken::generate(client_id, connect_user_data);
        let mut scratch = [0; NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES];
        token.write(&mut io::Cursor::new(&mut scratch[..]))?;

        let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        crypto::encode(&mut token_data[..], &scratch[..], None, challenge_sequence, challenge_key)?;

        Ok(ChallengePacket {
            token_sequence: challenge_sequence,
            token_data: token_data
        })
    }

    #[cfg(test)]
    pub fn decode(&self, challenge_key: &[u8; NETCODE_KEY_BYTES]) -> Result<ChallengeToken, ChallengeEncodeError> {
        let mut decoded = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        crypto::decode(&mut decoded, &self.token_data, None, self.token_sequence, challenge_key)?;

        ChallengeToken::read(&mut io::Cursor::new(&decoded[..])).map_err(|e| e.into())
    }

    pub fn read<R>(source: &mut R) -> Result<ChallengePacket, io::Error> where R: io::Read {
        let token_sequence = source.read_u64::<LittleEndian>()?;
        let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        source.read_exact(&mut token_data)?;

        Ok(ChallengePacket {
            token_sequence: token_sequence,
            token_data: token_data
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<LittleEndian>(self.token_sequence)?;
        out.write(&self.token_data)?;

        Ok(())
    }
}

pub struct ResponsePacket {
    pub token_sequence: u64,
    pub token_data: [u8; NETCODE_CHALLENGE_TOKEN_BYTES]
}

impl ResponsePacket {
    pub fn read<R>(source: &mut R) -> Result<ResponsePacket, io::Error> where R: io::Read {
        let token_sequence = source.read_u64::<LittleEndian>()?;
        let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        source.read_exact(&mut token_data)?;

        Ok(ResponsePacket {
            token_sequence: token_sequence,
            token_data: token_data
        })
    }

    pub fn decode(&self, challenge_key: &[u8; NETCODE_KEY_BYTES]) -> Result<ChallengeToken, ChallengeEncodeError> {
        let mut decoded = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        crypto::decode(&mut decoded, &self.token_data, None, self.token_sequence, challenge_key)?;

        ChallengeToken::read(&mut io::Cursor::new(&decoded[..])).map_err(|e| e.into())
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<LittleEndian>(self.token_sequence)?;
        out.write(&self.token_data)?;

        Ok(())
    }
}

pub struct KeepAlivePacket {
    pub client_idx: i32,
    pub max_clients: i32
}

impl KeepAlivePacket {
    pub fn read<R>(source: &mut R) -> Result<KeepAlivePacket, io::Error> where R: io::Read {
        Ok(KeepAlivePacket {
            client_idx: source.read_i32::<LittleEndian>()?,
            max_clients: source.read_i32::<LittleEndian>()?
        })
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_i32::<LittleEndian>(self.client_idx)?;
        out.write_i32::<LittleEndian>(self.max_clients)?;

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

    for i in 0..8 {
        test_seq_value(bits);
        assert_eq!(i+1, sequence_bytes_required(bits));
        bits <<= 8;
    }
}

#[cfg(test)]
fn test_encode_decode<V>(
        packet: Packet,
        payload: Option<&[u8]>,
        private_key: Option<[u8; NETCODE_KEY_BYTES]>,
        verify: V)
            where V: Fn(Packet)
        {
    let sequence = if let Packet::ConnectionRequest(_) = packet {
        0x0
    } else {
        0xCCDD
    };

    let protocol_id = 0xFFCC;
    let pkey = crypto::generate_key();

    let mut scratch = [0; NETCODE_MAX_PACKET_SIZE];
    let mut out_packet = [0; NETCODE_MAX_PAYLOAD_SIZE];
    let length = encode(&mut scratch[..], protocol_id, &packet, Some((sequence, &pkey)), payload).unwrap();
    match decode(&scratch[..length], protocol_id, Some(&pkey), &mut out_packet) {
        Ok((s,p)) => {
            assert_eq!(s, sequence);
            verify(p);
        },
        Err(e) => assert!(false, "{:?}", e)
    }

    if let Some(in_payload) = payload {
        for i in 0..in_payload.len() {
            assert_eq!(in_payload[i], out_packet[i]);
        }
    }

    unsafe {
        #[allow(unused_variables)]
        let lock = ::common::test::FFI_LOCK.lock().unwrap();

        use capi;

        let mut replay: capi::netcode_replay_protection_t = ::std::mem::uninitialized();
        capi::netcode_replay_protection_reset(&mut replay);

        let allowed_packets = [1; capi::NETCODE_CONNECTION_NUM_PACKETS as usize];

        // todo: this needs to be updated to support the allocator context/function
        /*
        let mut allocator_context = ::std::ptr::null_mut();

        let result = capi::netcode_read_packet(
            scratch.as_mut_ptr(), length as i32, //data
            &mut sequence,
            pkey.as_mut_ptr(), //Recv private key
            protocol_id, //Protocol id
            0, //Current timestamp
            final_pkey, //Private key
            allowed_packets.as_mut_ptr(), //Allowed packets
            &mut replay, //Replay protection
            allocator_context, // Allocator context
            allocator_function); // Allocator function

        assert!(result != ::std::ptr::null_mut());

        capi::free(result);
        */
    }
}

#[test]
fn test_conn_packet() {
    use token;
    use std::net::SocketAddr;
    use std::str::FromStr;

    let protocol_id = 0xFFCC;
    let sequence = 0xCCDD;
    let pkey = crypto::generate_key();

    let token = token::ConnectToken::generate(
                        [SocketAddr::from_str("127.0.0.1:8080").unwrap()].iter().cloned(),
                        &pkey,
                        30, //Expire
                        sequence,
                        protocol_id,
                        0xFFEE, //Client Id
                        None).unwrap();

    let packet = Packet::ConnectionRequest(ConnectionRequestPacket {
        version: NETCODE_VERSION_STRING.clone(),
        protocol_id: protocol_id,
        token_expire: token.expire_utc,
        sequence: sequence,
        private_data: token.private_data
    });

    test_encode_decode(packet,
        None,
        Some(pkey),
        |p| {
            match p {
                Packet::ConnectionRequest(p) => {
                    for i in 0..p.version.len() {
                        assert_eq!(p.version[i], NETCODE_VERSION_STRING[i], "mismatch at index {}", i);
                    }

                    assert_eq!(p.protocol_id, protocol_id);
                    assert_eq!(p.token_expire, token.expire_utc);
                    assert_eq!(p.sequence, sequence);

                    for i in 0..p.private_data.len() {
                        assert_eq!(p.private_data[i], token.private_data[i]);
                    }
                },
                _ => assert!(false)
            }
        });
}

#[test]
fn test_conn_denied_packet() {
    test_encode_decode(
        Packet::ConnectionDenied,
        None,
        None,
        |p| {
            match p {
                Packet::ConnectionDenied => (),
                _ => assert!(false)
            }
        });
}

#[test]
fn test_challenge_packet() {
    let token_sequence = 0xFFDD;
    let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
    for i in 0..token_data.len() {
        token_data[i] = i as u8;
    }

    test_encode_decode(
        Packet::Challenge(ChallengePacket {
            token_sequence: token_sequence,
            token_data: token_data
        }),
        None,
        None,
        |p| {
            match p {
                Packet::Challenge(p) => {
                    assert_eq!(p.token_sequence, token_sequence);
                    for i in 0..token_data.len() {
                        assert_eq!(p.token_data[i], token_data[i]);
                    }
                },
                _ => assert!(false)
            }
        }
    );
}

#[test]
fn test_response_packet() {
    let token_sequence = 0xFFDD;
    let mut token_data = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
    for i in 0..token_data.len() {
        token_data[i] = i as u8;
    }

    test_encode_decode(
        Packet::Response(ResponsePacket {
            token_sequence: token_sequence,
            token_data: token_data
        }),
        None,
        None,
        |p| {
            match p {
                Packet::Response(p) => {
                    assert_eq!(p.token_sequence, token_sequence);
                    for i in 0..token_data.len() {
                        assert_eq!(p.token_data[i], token_data[i]);
                    }
                },
                _ => assert!(false)
            }
        }
    );
}

#[test]
fn test_keep_alive_packet() {
    let client_idx = 5;
    let max_clients = 10;

    test_encode_decode(
        Packet::KeepAlive(KeepAlivePacket {
            client_idx: client_idx,
            max_clients: max_clients
        }),
        None,
        None,
        |p| {
            match p {
                Packet::KeepAlive(p) => {
                    assert_eq!(p.client_idx, client_idx);
                },
                _ => assert!(false)
            }
        }
    );
}

#[test]
fn test_payload_packet() {
    for i in 1..NETCODE_MAX_PAYLOAD_SIZE {
        let data = (0..i).map(|v| v as u8).collect::<Vec<u8>>();

        test_encode_decode(
            Packet::Payload(i),
            Some(&data[..]),
            None,
            |p| {
                match p {
                    Packet::Payload(c) => {
                        assert_eq!(c, i)
                    },
                    _ => assert!(false)
                }
            });
    }
}

#[test]
fn test_decode_challenge_token() {
    let mut user_data = [0; NETCODE_USER_DATA_BYTES];
    for i in 0..user_data.len() {
        user_data[i] = i as u8;
    }

    let client_id = 5;
    let challenge_sequence = 0xFED;
    let mut challenge_key = crypto::generate_key();

    let challenge_packet = ChallengePacket::generate(client_id,
                            &user_data,
                            challenge_sequence,
                            &challenge_key).unwrap();

    let decoded = challenge_packet.decode(&challenge_key).unwrap();
    assert_eq!(decoded.client_id, client_id);
    for i in 0..user_data.len() {
        assert_eq!(user_data[i], decoded.user_data[i]);
    }

   unsafe {
        #[allow(unused_variables)]
        let lock = ::common::test::FFI_LOCK.lock().unwrap();

        use capi;

        let mut capi_scratch = [0; NETCODE_CHALLENGE_TOKEN_BYTES];
        capi_scratch.copy_from_slice(&challenge_packet.token_data);

        let decode = capi::netcode_decrypt_challenge_token(
            capi_scratch.as_mut_ptr(),
            capi_scratch.len() as i32,
            challenge_sequence,
            challenge_key.as_mut_ptr());

        assert_eq!(decode, 1);

        let mut native_token: capi::netcode_challenge_token_t = ::std::mem::uninitialized();

        let serialize = capi::netcode_read_challenge_token(
            capi_scratch.as_mut_ptr(),
            capi_scratch.len() as i32,
            &mut native_token);

        assert_eq!(serialize, 1);
        assert_eq!(native_token.client_id, client_id);
        for i in 0..user_data.len() {
            assert_eq!(user_data[i], native_token.user_data[i]);
        }
    }
}
