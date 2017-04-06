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

#[cfg(test)]
pub mod test {
    use mio::*;

    use std::net::SocketAddr;
    use std::io;
    use std::cmp;

    pub struct MockSocket {
        outgoing: Vec<(SocketAddr, Vec<u8>)>,
        incoming: Vec<(SocketAddr, Vec<u8>)>,

        local: SocketAddr,
        remote: Option<SocketAddr>,

        event_registration: Registration,
        event_ready: SetReadiness
    }

    impl Evented for MockSocket {
        fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<(), io::Error> {
            self.event_registration.register(poll, token, interest, opts)
        }

        fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<(), io::Error> {
            self.event_registration.reregister(poll, token, interest, opts)
        }

        fn deregister(&self, poll: &Poll) -> Result<(), io::Error> {
            self.event_registration.deregister(poll)
        }
    }

    impl super::SocketProvider<MockSocket> for MockSocket {
        fn bind(addr: &SocketAddr) -> Result<MockSocket, io::Error> {
            let (registration, ready) = Registration::new2();

            Ok(MockSocket {
                outgoing: vec!(),
                incoming: vec!(),
                local: addr.clone(),
                remote: None,
                event_registration: registration,
                event_ready: ready
            })
        }

        fn local_addr(&self) -> Result<SocketAddr, io::Error> {
            Ok(self.local)
        }

        fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
            if let Some((addr, packet)) =  self.incoming.pop() {
                if buf.len() < packet.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "buffer was to small to recieve packet"))
                }

                buf[..packet.len()].copy_from_slice(&packet);
                Ok(Some((packet.len(),addr)))
            } else {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
            }
        }

        fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<Option<usize>, io::Error> {
            self.outgoing.push((addr.clone(), buf.to_vec()));

            Ok(Some(buf.len()))
        }


        fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error> {
            self.remote = Some(addr);

            Ok(())
        }

        fn send(&mut self, buf: &[u8]) -> Result<Option<usize>, io::Error> {
            if let Some(remote) = self.remote {
                self.outgoing.push((remote, buf.to_vec()));
                Ok(Some(buf.len()))
            } else {
                Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected"))
            }
        }

        fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, io::Error> {
            self.recv_from(buf).and_then(|opt| {
                opt.map_or(Err(io::Error::new(io::ErrorKind::WouldBlock, "no data")),
                    |(size, addr)| {
                        if addr == self.local {
                            Ok(Some(size))
                        } else {
                            Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
                        }
                    })
                })
        }
    }
}
