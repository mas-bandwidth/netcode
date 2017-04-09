use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::io;
use std::io::Write;
use std::time;
use byteorder::{WriteBytesExt, ReadBytesExt, LittleEndian, BigEndian};

use common::*;
use crypto;

#[derive(Debug)]
pub enum GenerateError {
    /// Too many connect addresses encoded.
    MaxHostCount,
    /// IO error occured when writing token.
    GenericIO(io::Error),
    /// Encryption of private data failed.
    Encrypt(crypto::EncryptError)
}

impl From<io::Error> for GenerateError {
    fn from(err: io::Error) -> GenerateError {
        GenerateError::GenericIO(err)
    }
}

impl From<crypto::EncryptError> for GenerateError {
    fn from(err: crypto::EncryptError) -> GenerateError {
        GenerateError::Encrypt(err)
    }
}

#[derive(Debug)]
pub enum DecodeError {
    /// Private key failed to decode auth data.
    InvalidPrivateKey,
    /// Invalid version number was supplied.
    InvalidVersion,
    /// IO error occured when reading token.
    GenericIO(io::Error),
    /// Decryption of private data failed.
    Decrypt(crypto::EncryptError)
}

impl From<io::Error> for DecodeError {
    fn from(err: io::Error) -> DecodeError {
        DecodeError::GenericIO(err)
    }
}

impl From<crypto::EncryptError> for DecodeError {
    fn from(err: crypto::EncryptError) -> DecodeError {
        DecodeError::Decrypt(err)
    }
}

const NETCODE_ADDRESS_IPV4: u8 = 1;
const NETCODE_ADDRESS_IPV6: u8 = 2;

const NETCODE_ADDITIONAL_DATA_SIZE: usize = NETCODE_VERSION_LEN + 8 + 8;

/// Token used by clients to connect and authenticate to a netcode `Server`
pub struct ConnectToken {
    /// Protocl ID for messages relayed by netcode.
    pub protocol: u64,
    /// Token creation time in ms from unix epoch.
    pub create_utc: u64,
    /// Token expire time in ms from unix epoch.
    pub expire_utc: u64,
    /// Nonce sequence for decoding private data.
    pub sequence: u64,
    /// Private data encryped with server's private key(separate from client <-> server keys).
    pub private_data: [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
    /// List of hosts this token supports connecting to.
    pub hosts: HostList,
    /// Private key for client -> server communcation.
    pub client_to_server_key: [u8; NETCODE_KEY_BYTES],
    /// Private key for server -> client communcation.
    pub server_to_client_key: [u8; NETCODE_KEY_BYTES],
    /// Time in seconds connection should wait before disconnecting
    pub timeout_sec: u32
}

pub struct PrivateData {
    /// Unique client id, determined by the server.
    pub client_id: u64,
    /// Secondary host list to authoritatively determine which hosts clients can connect to.
    pub hosts: HostList,
    /// Private key for client -> server communcation.
    pub client_to_server_key: [u8; NETCODE_KEY_BYTES],
    /// Private key for server -> client communcation.
    pub server_to_client_key: [u8; NETCODE_KEY_BYTES],
    /// Server-specific user data.
    pub user_data: [u8; NETCODE_USER_DATA_BYTES]
}

#[derive(Clone,Debug)]
pub struct HostList {
    hosts: [Option<SocketAddr>; NETCODE_MAX_SERVERS_PER_CONNECT]
}

fn generate_user_data() -> [u8; NETCODE_USER_DATA_BYTES] {
    let mut user_data: [u8; NETCODE_USER_DATA_BYTES] = 
        [0; NETCODE_USER_DATA_BYTES];

    crypto::random_bytes(&mut user_data);

    user_data
}

fn generate_additional_data(protocol: u64, expire_utc: u64) -> Result<[u8; NETCODE_ADDITIONAL_DATA_SIZE], io::Error> {
    let mut scratch = [0; NETCODE_ADDITIONAL_DATA_SIZE];

    {
        let mut out = io::Cursor::new(&mut scratch[..]);

        out.write(NETCODE_VERSION_STRING)?;
        out.write_u64::<LittleEndian>(protocol)?;
        out.write_u64::<LittleEndian>(expire_utc)?;
    }

    Ok(scratch)
}

pub fn get_time_now() -> u64 {
    time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs()
}

impl ConnectToken {
    /// Generates a new connection token.
    /// `addrs` - List of allowed hosts to connect to.
    /// `private_key` - Server private key that will be used to authenticate requests.
    /// `expire_sec` - How long this token is valid for in seconds.
    /// `sequence` - Sequence nonce to use, this should always be unique per server, per token. Use a continously incrementing counter should be sufficient for most cases.
    /// `protocol` - Client specific protocol.
    /// `client_id` - Unique client identifier.
    /// `user_data` - Client specific userdata.
    pub fn generate<H>(hosts: H,
                       private_key: &[u8; NETCODE_KEY_BYTES],
                       expire_sec: usize,
                       sequence: u64,
                       protocol: u64,
                       client_id: u64,
                       user_data: Option<&[u8; 256]>)
                       -> Result<ConnectToken, GenerateError>
                          where H: ExactSizeIterator<Item=SocketAddr> {
        if hosts.len() > NETCODE_MAX_SERVERS_PER_CONNECT {
            return Err(GenerateError::MaxHostCount)
        }

        let now = get_time_now();
        let expire = now + expire_sec as u64;

        let decoded_data = PrivateData::new(client_id, hosts, user_data);

        let mut private_data = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
        decoded_data.encode(&mut private_data, protocol, expire, sequence, private_key)?;

        Ok(ConnectToken {
            hosts: decoded_data.hosts.clone(),
            create_utc: now,
            expire_utc: expire,
            protocol: protocol,
            sequence: sequence,
            private_data: private_data,
            client_to_server_key: decoded_data.client_to_server_key,
            server_to_client_key: decoded_data.server_to_client_key,
            timeout_sec: NETCODE_TIMEOUT_SECONDS
        })
    }

    /// Decodes the private data stored by this connection token.
    /// `private_key` - Server's private key used to generate this token.
    /// `sequence` - Nonce sequence used to generate this token.
    pub fn decode(&mut self, private_key: &[u8; NETCODE_KEY_BYTES]) -> Result<PrivateData, DecodeError> {
        PrivateData::decode(&self.private_data, self.protocol, self.expire_utc, self.sequence, private_key)
    }

    /// Encodes a ConnectToken into a `io::Write`.
    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write(NETCODE_VERSION_STRING)?;
        out.write_u64::<LittleEndian>(self.protocol)?;
        out.write_u64::<LittleEndian>(self.create_utc)?;
        out.write_u64::<LittleEndian>(self.expire_utc)?;
        out.write_u64::<LittleEndian>(self.sequence)?;
        out.write(&self.private_data)?;
        self.hosts.write(out)?;
        out.write(&self.client_to_server_key)?;
        out.write(&self.server_to_client_key)?;
        out.write_u32::<LittleEndian>(self.timeout_sec)?;

        Ok(())
    }

    /// Decodes a ConnectToken from an `io::Read`.
    pub fn read<R>(source: &mut R) -> Result<ConnectToken, DecodeError> where R: io::Read {
        let mut version = [0; NETCODE_VERSION_LEN];

        source.read_exact(&mut version)?;

        if &version != NETCODE_VERSION_STRING {
            return Err(DecodeError::InvalidVersion)
        }

        let protocol = source.read_u64::<LittleEndian>()?;
        let create_utc = source.read_u64::<LittleEndian>()?;
        let expire_utc = source.read_u64::<LittleEndian>()?;
        let sequence = source.read_u64::<LittleEndian>()?;

        let mut private_data = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
        source.read_exact(&mut private_data)?;

        let hosts = HostList::read(source)?;

        let mut client_to_server_key = [0; NETCODE_KEY_BYTES];
        source.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = [0; NETCODE_KEY_BYTES];
        source.read_exact(&mut server_to_client_key)?;

        let timeout_sec = source.read_u32::<LittleEndian>()?;

        Ok(ConnectToken {
            hosts: hosts,
            create_utc: create_utc,
            expire_utc: expire_utc,
            protocol: protocol,
            sequence: sequence,
            private_data: private_data,
            client_to_server_key: client_to_server_key,
            server_to_client_key: server_to_client_key,
            timeout_sec: timeout_sec
        })
    }
}

impl PrivateData {
    pub fn new<H>(client_id: u64, hosts: H, user_data: Option<&[u8; NETCODE_USER_DATA_BYTES]>) -> PrivateData where H: Iterator<Item=SocketAddr> {
        let final_user_data = match user_data {
            Some(u) => {
                let mut copy_ud: [u8; NETCODE_USER_DATA_BYTES] = [0; NETCODE_USER_DATA_BYTES];
                copy_ud[..u.len()].copy_from_slice(u);
                copy_ud
            },
            None => generate_user_data()
        };

        let client_to_server_key = crypto::generate_key();
        let server_to_client_key = crypto::generate_key();

        PrivateData {
            client_id: client_id,
            hosts: HostList::new(hosts),
            user_data: final_user_data,
            client_to_server_key: client_to_server_key,
            server_to_client_key: server_to_client_key
        }
    }

    pub fn decode(encoded: &[u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
                  protocol_id: u64,
                  expire_utc: u64,
                  sequence: u64,
                  private_key: &[u8; NETCODE_KEY_BYTES])
                  -> Result<PrivateData, DecodeError> {
        let additional_data = generate_additional_data(protocol_id, expire_utc)?;
        let mut decoded = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - crypto::NETCODE_ENCRYPT_EXTA_BYTES];

        crypto::decode(&mut decoded, encoded, Some(&additional_data), sequence, private_key)?;

        Ok(PrivateData::read(&mut io::Cursor::new(&decoded[..]))?)
    }

    pub fn encode(&self, 
                  out: &mut [u8; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES],
                  protocol_id: u64,
                  expire_utc: u64,
                  sequence: u64,
                  private_key: &[u8; NETCODE_KEY_BYTES])
                  -> Result<(), GenerateError> {
        let additional_data = generate_additional_data(protocol_id, expire_utc)?;
        let mut scratch = [0; NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - crypto::NETCODE_ENCRYPT_EXTA_BYTES];

        self.write(&mut io::Cursor::new(&mut scratch[..]))?;

        crypto::encode(&mut out[..], &scratch, Some(&additional_data), sequence, private_key)?;

        Ok(())
    }

    fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u64::<LittleEndian>(self.client_id)?;

        self.hosts.write(out)?;
        out.write(&self.client_to_server_key)?;
        out.write(&self.server_to_client_key)?;

        out.write(&self.user_data)?;

        Ok(())
    }

    fn read<R>(source: &mut R) -> Result<PrivateData, io::Error> where R: io::Read {
        let client_id = source.read_u64::<LittleEndian>()?;
        let hosts = HostList::read(source)?;

        let mut client_to_server_key = [0; NETCODE_KEY_BYTES];
        source.read_exact(&mut client_to_server_key)?;

        let mut server_to_client_key = [0; NETCODE_KEY_BYTES];
        source.read_exact(&mut server_to_client_key)?;

        let mut user_data = [0; NETCODE_USER_DATA_BYTES];
        source.read_exact(&mut user_data)?;

        Ok(PrivateData {
            hosts: hosts,
            client_id: client_id,
            client_to_server_key: client_to_server_key,
            server_to_client_key: server_to_client_key,
            user_data: user_data
        })
    }
}

impl HostList {
    pub fn new<I>(hosts: I) -> HostList where I: Iterator<Item=SocketAddr> {
        let mut final_hosts = [None; NETCODE_MAX_SERVERS_PER_CONNECT];

        for (i,host) in hosts.enumerate().take(NETCODE_MAX_SERVERS_PER_CONNECT) {
            final_hosts[i] = Some(host);
        }

        HostList {
            hosts: final_hosts
        }
    }

    pub fn read<R>(source: &mut R) -> Result<HostList, io::Error> where R: io::Read {
        let host_count = source.read_u32::<LittleEndian>()?;
        let mut hosts = [None; NETCODE_MAX_SERVERS_PER_CONNECT];

        for i in 0..host_count as usize {
            let host_type = source.read_u8()?;

            match host_type {
                NETCODE_ADDRESS_IPV4 => {
                    let ip = source.read_u32::<BigEndian>()?;
                    let port = source.read_u16::<LittleEndian>()?;

                    hosts[i] = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
                },
                NETCODE_ADDRESS_IPV6 => {
                    let mut ip = [0; 16];
                    source.read_exact(&mut ip)?;
                    let port = source.read_u16::<LittleEndian>()?;

                    hosts[i] = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
                },
                _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown ip address type"))
            }
        }

        Ok(HostList {
            hosts: hosts
        })
    }

    pub fn get(&self) -> HostIterator {
        HostIterator {
            hosts: self,
            idx: 0
        }
    }

    pub fn write<W>(&self, out: &mut W) -> Result<(), io::Error> where W: io::Write {
        out.write_u32::<LittleEndian>(self.get().len() as u32)?;
        for host in self.get() {
            match host {
                SocketAddr::V4(addr) => {
                    out.write_u8(NETCODE_ADDRESS_IPV4)?;
                    let ip = addr.ip().octets();

                    for i in 0..4 {
                        out.write_u8(ip[i])?;
                    }
                },
                SocketAddr::V6(addr) => {
                    out.write_u8(NETCODE_ADDRESS_IPV6)?;
                    let ip = addr.ip().octets();

                    for i in 0..16 {
                        out.write_u8(ip[i])?;
                    }
                }
            }
            out.write_u16::<LittleEndian>(host.port())?;
        }

        Ok(())
    }
}

impl PartialEq for HostList {
    fn eq(&self, other: &HostList) -> bool {
        self.hosts == other.hosts
    }
}

/// Iterator for hosts held by a `ConnectToken`
pub struct HostIterator<'a> {
    hosts: &'a HostList,
    idx: usize
}

impl<'a> Iterator for HostIterator<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        if self.idx > self.hosts.hosts.len() {
            return None
        }

        let result = self.hosts.hosts[self.idx];
        self.idx += 1;

        result
    }
}

impl<'a> ExactSizeIterator for HostIterator<'a> {
    fn len(&self) -> usize {
        if self.hosts.hosts[0].is_none() {
            return 0
        }

        match self.hosts.hosts.iter().position(|h| h.is_none()) {
            Some(idx) => idx,
            None => self.hosts.hosts.len()
        }
    }
}

#[cfg(test)]
use std::str::FromStr;

#[test]
fn read_write() {
    let mut private_key = [0; NETCODE_KEY_BYTES];
    crypto::random_bytes(&mut private_key);

    let mut user_data = [0; NETCODE_USER_DATA_BYTES];
    crypto::random_bytes(&mut user_data);

    let expire = 30;
    let sequence = 1;
    let protocol = 0x112233445566;
    let client_id = 0x665544332211;

    let token = ConnectToken::generate(
                        [SocketAddr::from_str("127.0.0.1:8080").unwrap()].iter().cloned(),
                        &private_key,
                        expire,
                        sequence,
                        protocol,
                        client_id,
                        Some(&user_data)).unwrap();

    let mut scratch = [0; NETCODE_CONNECT_TOKEN_BYTES];
    token.write(&mut io::Cursor::new(&mut scratch[..])).unwrap();

    let read = ConnectToken::read(&mut io::Cursor::new(&scratch[..])).unwrap();

    assert_eq!(read.hosts, token.hosts);
    for i in 0..read.private_data.len() {
        assert_eq!(read.private_data[i], token.private_data[i], "Mismatch at index {}", i);
    }
    assert_eq!(read.expire_utc, token.expire_utc);
    assert_eq!(read.create_utc, token.create_utc);
    assert_eq!(read.sequence, token.sequence);
    assert_eq!(read.protocol, token.protocol);
    assert_eq!(read.timeout_sec, NETCODE_TIMEOUT_SECONDS);
}

#[test]
fn decode() {
    let mut private_key = [0; NETCODE_KEY_BYTES];
    crypto::random_bytes(&mut private_key);

    let mut user_data = [0; NETCODE_USER_DATA_BYTES];
    crypto::random_bytes(&mut user_data);

    let expire = 30;
    let sequence = 1;
    let protocol = 0x112233445566;
    let client_id = 0x665544332211;

    let mut token = ConnectToken::generate(
                        [SocketAddr::from_str("127.0.0.1:8080").unwrap()].iter().cloned(),
                        &private_key,
                        expire,
                        sequence,
                        protocol,
                        client_id,
                        Some(&user_data)).unwrap();
    
    let decoded = token.decode(&private_key).unwrap();

    assert_eq!(decoded.hosts, token.hosts);
    assert_eq!(decoded.client_id, client_id);
    assert_eq!(decoded.client_to_server_key, token.client_to_server_key);
    assert_eq!(decoded.server_to_client_key, token.server_to_client_key);

    for i in 0..user_data.len() {
        assert_eq!(decoded.user_data[i], user_data[i]);
    }
}

#[test]
fn interop_read() {
    use wrapper;

    let mut private_key = [0; NETCODE_KEY_BYTES];
    crypto::random_bytes(&mut private_key);

    let mut user_data = [0; NETCODE_USER_DATA_BYTES];
    crypto::random_bytes(&mut user_data);

    let expire = 30;
    let sequence = 1;
    let protocol = 0x112233445566;
    let client_id = 0x665544332211;

    let result = wrapper::ConnectToken::from_hosts(
            ["127.0.0.1:8080".to_string()].iter().cloned(),
            &private_key,
            expire,
            client_id,
            protocol,
            sequence).unwrap();

    let conv = ConnectToken::read(&mut io::Cursor::new(result.get_bytes())).unwrap();

    assert_eq!(conv.sequence, sequence);
    assert_eq!(conv.protocol, protocol);
    assert_eq!(conv.expire_utc, conv.create_utc + expire as u64);
}

#[test]
fn interop_write() {
    use wrapper;

    let mut private_key = [0; NETCODE_KEY_BYTES];
    crypto::random_bytes(&mut private_key);

    let mut user_data = [0; NETCODE_USER_DATA_BYTES];
    crypto::random_bytes(&mut user_data);

    let expire = 30;
    let sequence = 1;
    let protocol = 0x112233445566;
    let client_id = 0x665544332211;

    let token = ConnectToken::generate(
                        [SocketAddr::from_str("127.0.0.1:8080").unwrap()].iter().cloned(),
                        &private_key,
                        expire,
                        sequence,
                        protocol,
                        client_id,
                        Some(&user_data)).unwrap();

    let mut scratch = [0; NETCODE_CONNECT_TOKEN_BYTES];
    token.write(&mut io::Cursor::new(&mut scratch[..])).unwrap();

    unsafe {
        let mut output: wrapper::private::netcode_connect_token_t = ::std::mem::uninitialized();
        assert_eq!(wrapper::private::netcode_read_connect_token(scratch.as_mut_ptr(), scratch.len() as i32, &mut output), 1);
        
        assert_eq!(output.sequence, sequence);
        assert_eq!(output.expire_timestamp, output.create_timestamp + expire as u64);
        assert_eq!(output.protocol_id, protocol);
    }
}

