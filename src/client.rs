use netcode::*;
use token::*;
use util;

use std::ffi::CString;

#[derive(Debug)]
pub enum ClientError {
    Create,
    Token
}

#[derive(Debug, PartialEq)]
pub enum ClientState {
    ConnectTokenExpired,
    InvalidConnectToken,
    ConnectionTimedOut,
    ConnectionResponseTimeout,
    ConnectionRequestTimeout,
    ConnectionDenied,
    Disconnected,
    SendingConnectionRequest,
    SendingConnectionResponse,
    Connected,
    Unknown
}

impl ClientState {
    fn from_code(code: i32) -> ClientState {
        match code {
            NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED => ClientState::ConnectTokenExpired,
            NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN => ClientState::InvalidConnectToken,
            NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT => ClientState::ConnectionTimedOut,
            NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMEOUT => ClientState::ConnectionResponseTimeout,
            NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMEOUT => ClientState::ConnectionRequestTimeout,
            NETCODE_CLIENT_STATE_CONNECTION_DENIED => ClientState::ConnectionDenied,
            NETCODE_CLIENT_STATE_DISCONNECTED => ClientState::Disconnected,
            NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST => ClientState::SendingConnectionRequest,
            NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE => ClientState::SendingConnectionResponse,
            NETCODE_CLIENT_STATE_CONNECTED => ClientState::Connected,
            _ => ClientState::Unknown
       }
    }
}

pub struct Client {
    handle: *mut netcode_client_t
}

impl Client {
    pub fn new_with_host<S>(client_address: S, token: &ConnectToken) -> Result<Client, ClientError> where S: Into<String> {
        util::global_init();

        unsafe {
            let cstr_client_address = CString::new(client_address.into()).unwrap();
            let client_ptr = netcode_client_create(cstr_client_address.as_ptr(), 0.0);
            
            if client_ptr == ::std::ptr::null_mut() {
                return Err(ClientError::Create)
            }

            //Construct client so we destroy it if an further step fails
            let client = Client {
                handle: client_ptr
            };

            netcode_client_connect(client_ptr, token.get_bytes().as_ptr());

            Ok(client)
        }
    }

    pub fn new(token: &ConnectToken) -> Result<Client, ClientError> {
        Self::new_with_host("127.0.0.1", token)
    }

    pub fn state(&self) -> ClientState {
        unsafe {
            ClientState::from_code(netcode_client_state(self.handle))
        }
    }

    pub fn update(&mut self, time: f64) {
        unsafe {
            netcode_client_update(self.handle, time);
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), ::SendError> {
        if data.len() > NETCODE_MAX_PACKET_SIZE {
            return Err(::SendError::LengthExceeded)
        }

        unsafe {
            netcode_client_send_packet(self.handle, data.as_ptr(), data.len() as i32);
        }

        Ok(())
    }

    pub fn recv<'a>(&'a mut self) -> Option<ClientPacket<'a>> {
        let mut bytes: ::std::os::raw::c_int = 0;

        unsafe {
            let ptr = netcode_client_receive_packet(self.handle, &mut bytes);

            if ptr == ::std::ptr::null_mut() {
                return None
            }

            Some(ClientPacket::new(self, ptr as *mut u8, bytes as usize))
        }
    }

    pub fn disconnect(&mut self) {
        unsafe {
            netcode_client_disconnect(self.handle)
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            netcode_client_destroy(self.handle);
            util::global_term();
        }
    }
}

pub struct ClientPacket<'a> {
    client: &'a Client,
    data: *mut u8,
    size: usize
}

impl<'a> ClientPacket<'a> {
    fn new(client: &'a Client, data: *mut u8, size: usize) -> ClientPacket<'a> {
        ClientPacket {
            client: client,
            data: data,
            size: size
        }
    }

    pub fn data(&self) -> &'a [u8] {
        unsafe {
            ::std::slice::from_raw_parts(self.data, self.size)
        }
    }
}

impl<'a> Drop for ClientPacket<'a> {
    fn drop(&mut self) {
        unsafe {
            netcode_client_free_packet(self.client.handle, self.data as *mut ::std::os::raw::c_void);
        }
    }
}