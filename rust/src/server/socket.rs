use std::net::{SocketAddr, ToSocketAddrs};
use std::io;

use mio;

pub trait SocketProvider<I> where I: mio::Evented {
    fn bind(addr: &SocketAddr) -> Result<I, io::Error>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error>;

    fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error>;
    fn send(&mut self, buf: &[u8]) -> Result<Option<usize>, io::Error>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, io::Error>;
}

impl SocketProvider<mio::udp::UdpSocket> for mio::udp::UdpSocket {
    fn bind(addr: &SocketAddr) -> Result<mio::udp::UdpSocket, io::Error> {
        mio::udp::UdpSocket::bind(addr)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        mio::udp::UdpSocket::recv_from(self, buf)
    }

    fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error> {
        mio::udp::UdpSocket::connect(self, addr)
    }

    fn send(&mut self, buf: &[u8]) -> Result<Option<usize>, io::Error> {
        mio::udp::UdpSocket::send(self, buf)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, io::Error> {
        mio::udp::UdpSocket::recv(self, buf)
    }
}