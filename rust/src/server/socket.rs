use std::net::SocketAddr;
use std::io;

use mio;
use net2;

pub trait SocketProvider<I> where I: mio::Evented {
    fn bind(addr: &SocketAddr) -> Result<I, io::Error>;
    fn local_addr(&self) -> Result<SocketAddr, io::Error>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error>;
    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<Option<usize>, io::Error>;

    fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error>;
    fn send(&mut self, buf: &[u8]) -> Result<Option<usize>, io::Error>;
    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, io::Error>;
}

impl SocketProvider<mio::udp::UdpSocket> for mio::udp::UdpSocket {
    fn bind(addr: &SocketAddr) -> Result<mio::udp::UdpSocket, io::Error> {
        let socket = net2::UdpBuilder::new_v4()?.reuse_address(true)?.bind(addr)?;
        mio::udp::UdpSocket::from_socket(socket)
    }

    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        mio::udp::UdpSocket::local_addr(self)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        mio::udp::UdpSocket::recv_from(self, buf)
    }

    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<Option<usize>, io::Error> {
        mio::udp::UdpSocket::send_to(self, buf, addr)
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