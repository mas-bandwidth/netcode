use std::net::{ToSocketAddrs, SocketAddr, UdpSocket};
use std::io;

pub const NETCODE_CONNECT_TOKEN_BYTES: usize = 4096;
pub const NETCODE_KEY_BYTES: usize = 32;
pub const NETCODE_USER_DATA_BYTES: usize = 256;
pub const NETCODE_CONNECT_TOKEN_PRIVATE_BYTES: usize = 1024;

pub const NETCODE_MAX_SERVERS_PER_CONNECT: usize = 16;

pub const NETCODE_MAX_CLIENTS: usize = 256;
pub const NETCODE_MAX_PACKET_SIZE: usize = 1200;

/// Trait that lets us mock out socket implemenations
/// in a way that doesn't impact out runtime.
pub trait Socket<I> {
    fn bind<A>(addr: A) -> Result<I, io::Error> where A: ToSocketAddrs;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error>;
    fn connect<A>(&mut self, addr: A) -> Result<(), io::Error> where A: ToSocketAddrs;
    fn send(&mut self, buf: &[u8]) -> Result<usize, io::Error>;
}

impl Socket<UdpSocket> for UdpSocket {
    fn bind<A>(addr: A) -> Result<UdpSocket, io::Error> where A: ToSocketAddrs {
        UdpSocket::bind(addr)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        self.recv_from(buf)
    }

    fn connect<A>(&mut self, addr: A) -> Result<(), io::Error> where A: ToSocketAddrs {
        self.connect(addr)
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.send(buf)
    }
}

pub struct MockedSocket {
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    sent: Vec<(SocketAddr,Vec<u8>)>,
    recv: Vec<(SocketAddr,Vec<u8>)>
}

impl Socket<MockedSocket> for MockedSocket {
    fn bind<A>(addr: A) -> Result<MockedSocket, io::Error> where A: ToSocketAddrs {
        Ok(MockedSocket {
            local_addr: try!(addr.to_socket_addrs()).next().unwrap(),
            remote_addr: None,
            sent: vec!(),
            recv: vec!()
        })
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        match self.recv.pop() {
            Some((addr, p)) => {
                buf[..p.len()].copy_from_slice(&p);
                Ok((p.len(), addr))
            },
            None => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "Would Block"))
            }
        }
    }

    fn connect<A>(&mut self, addr: A) -> Result<(), io::Error> where A: ToSocketAddrs {
        self.remote_addr = Some(try!(addr.to_socket_addrs()).next().unwrap());
        Ok(())
    }

    fn send(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.remote_addr {
            Some(addr) => {
                self.sent.push((addr, Vec::from(buf)));
                Ok(buf.len())
            },
            None => {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Not Connected"))
            }
        }
    }
}