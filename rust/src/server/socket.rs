use std::net::{SocketAddr, UdpSocket};
use std::io;
use std::time::Duration;

use net2;

pub trait SocketProvider<I,S> {
    fn new_state() -> S;
    fn bind(addr: &SocketAddr, state: &mut S) -> Result<I, io::Error>;
    fn local_addr(&self) -> Result<SocketAddr, io::Error>;
    fn set_recv_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error>;
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error>;
    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<usize, io::Error>;
}

impl SocketProvider<UdpSocket,()> for UdpSocket {
    fn new_state() -> () {
        ()
    }

    fn bind(addr: &SocketAddr, state: &mut ()) -> Result<UdpSocket, io::Error> {
        let socket = net2::UdpBuilder::new_v4()?.reuse_address(true)?.bind(addr)?;
        socket.set_nonblocking(true)?;

        Ok(socket)
    }

    fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        UdpSocket::local_addr(self)
    }

    fn set_recv_timeout(&mut self, duration: Option<Duration>) -> Result<(), io::Error> {
        match duration {
            Some(duration) => {
                self.set_nonblocking(false)?;
                self.set_read_timeout(Some(duration))
            },
            None => {
                self.set_nonblocking(true)
            }
        }
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        UdpSocket::recv_from(self, buf)
    }

    fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<usize, io::Error> {
        UdpSocket::send_to(self, buf, addr)
    }
}

#[cfg(test)]
pub mod capi_simulator {
    use super::*;
    use wrapper::private::*;

    use std::rc::{Rc, Weak};
    use std::cell::RefCell;
    use std::ffi::{CString, CStr};

    pub type SimulatorRef = Rc<RefCell<Simulator>>;

    pub struct Simulator {
        pub sim: *mut netcode_network_simulator_t
    }

    impl Drop for Simulator {
        fn drop(&mut self) {
            unsafe {
                netcode_network_simulator_destroy(self.sim);
            }
        }
    }

    pub struct SimulatedSocket {
        local_addr: SocketAddr,
        sim: Weak<RefCell<Simulator>>
    }

    fn addr_to_naddr(addr: &SocketAddr) -> Result<netcode_address_t, io::Error> {
        unsafe {
            let mut naddr: netcode_address_t = ::std::mem::uninitialized();
            let str_rep = CString::new(format!("{}", addr))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid string address"))?;

            match netcode_parse_address(str_rep.as_ptr(), &mut naddr) {
                1 => Ok(naddr),
                _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unable to parse addr"))
            }
        }
    }

    fn naddr_to_addr(naddr: &netcode_address_t) -> Result<SocketAddr, io::Error> {
        use std::str::FromStr;

        unsafe {
            let mut addr = [0; NETCODE_MAX_ADDRESS_STRING_LENGTH as usize];
            netcode_address_to_string(::std::mem::transmute(naddr), addr.as_mut_ptr());

            let cstr = CStr::from_ptr(addr.as_ptr());
            SocketAddr::from_str(cstr.to_str().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid UTF-8"))?)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Unable to parse address"))
        }
    }

    impl SocketProvider<SimulatedSocket, SimulatorRef> for SimulatedSocket {
        fn new_state() -> Rc<RefCell<Simulator>> {
            Rc::new(RefCell::new(Simulator {
                sim: unsafe { netcode_network_simulator_create() }
            }))
        }

        fn bind(addr: &SocketAddr, state: &mut SimulatorRef) -> Result<SimulatedSocket, io::Error> {
            Ok(SimulatedSocket {
                local_addr: addr.clone(),
                sim: Rc::downgrade(state)
            })
        }

        fn local_addr(&self) -> Result<SocketAddr, io::Error> {
            Ok(self.local_addr)
        }

        fn set_recv_timeout(&mut self, _duration: Option<Duration>) -> Result<(), io::Error> {
            Ok(())
        }

        fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
            unsafe {
                let mut packet = [::std::ptr::null_mut(); 1];
                let mut packet_len = 0;
                let mut addr: netcode_address_t = ::std::mem::uninitialized();
                let mut local_addr = addr_to_naddr(&self.local_addr)?;

                match self.sim.upgrade() {
                    Some(simref) => {
                        let result = netcode_network_simulator_receive_packets(
                            simref.borrow_mut().sim,
                            &mut local_addr,
                            packet.len() as i32,
                            packet.as_mut_ptr(),
                            &mut packet_len,
                            &mut addr); 

                        match result {
                            1 => {
                                let len = packet_len as usize;
                                buf[..len].copy_from_slice(::std::slice::from_raw_parts(packet[0], len));

                                free(::std::mem::transmute(packet[0]));
                                Ok((len as usize, naddr_to_addr(&addr)?))
                            },
                            _ => Err(io::Error::new(io::ErrorKind::WouldBlock, "No packets"))
                        }
                    }
                    None => Err(io::Error::new(io::ErrorKind::InvalidData, "Simulator released"))
                }
            }
        }

        fn send_to(&mut self, buf: &[u8], addr: &SocketAddr) -> Result<usize, io::Error> {
            let mut from = addr_to_naddr(&self.local_addr)?;
            let mut to = addr_to_naddr(addr)?;

            unsafe {
                match self.sim.upgrade() {
                    Some(simref) => {
                        netcode_network_simulator_send_packet(
                            simref.borrow_mut().sim,
                            &mut from,
                            &mut to,
                            ::std::mem::transmute(buf.as_ptr()),
                            buf.len() as i32); 
                        Ok(buf.len())
                    }
                    None => Err(io::Error::new(io::ErrorKind::InvalidData, "Simulator released"))
                }
            }

        }
    }
}