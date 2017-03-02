//@todo: Remove when we have implemented all fns
#[allow(dead_code)]
mod netcode;
mod util;   

use std::ffi::CString;

pub enum ClientError {
    Create,
    Token
}

pub enum SendError {
    LengthExceeded
}

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
            netcode::NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED => ClientState::ConnectTokenExpired,
            netcode::NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN => ClientState::InvalidConnectToken,
            netcode::NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT => ClientState::ConnectionTimedOut,
            netcode::NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMEOUT => ClientState::ConnectionResponseTimeout,
            netcode::NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMEOUT => ClientState::ConnectionRequestTimeout,
            netcode::NETCODE_CLIENT_STATE_CONNECTION_DENIED => ClientState::ConnectionDenied,
            netcode::NETCODE_CLIENT_STATE_DISCONNECTED => ClientState::Disconnected,
            netcode::NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST => ClientState::SendingConnectionRequest,
            netcode::NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE => ClientState::SendingConnectionResponse,
            netcode::NETCODE_CLIENT_STATE_CONNECTED => ClientState::Connected,
            _ => ClientState::Unknown
       }
    }
}

pub struct Client {
    handle: *mut netcode::netcode_client_t
}

impl Client {
    pub fn new_with_host<S>(client_address: S, token: &ConnectToken) -> Result<Client, ClientError> where S: Into<String> {
        util::global_init();

        unsafe {
            let cstr_client_address = CString::new(client_address.into()).unwrap();
            let client_ptr = netcode::netcode_client_create(cstr_client_address.as_ptr(), 0.0);
            
            if client_ptr == std::ptr::null_mut() {
                return Err(ClientError::Create)
            }

            //Construct client so we destroy it if an further step fails
            let client = Client {
                handle: client_ptr
            };

            netcode::netcode_client_connect(client_ptr, token.token.as_ptr());

            Ok(client)
        }
    }

    pub fn new(token: &ConnectToken) -> Result<Client, ClientError> {
        Self::new_with_host("::", token)
    }

    pub fn state(&self) -> ClientState {
        unsafe {
            ClientState::from_code(netcode::netcode_client_state(self.handle))
        }
    }

    pub fn update(&mut self, time: f64) {
        unsafe {
            netcode::netcode_client_update(self.handle, time);
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<(), SendError> {
        if data.len() > netcode::NETCODE_MAX_PACKET_SIZE {
            return Err(SendError::LengthExceeded)
        }

        unsafe {
            netcode::netcode_client_send_packet(self.handle, data.as_ptr(), data.len() as i32);
        }

        Ok(())
    }

    pub fn recv<'a>(&'a mut self) -> Option<ClientPacket<'a>> {
        let mut bytes: std::os::raw::c_int = 0;

        unsafe {
            let ptr = netcode::netcode_client_receive_packet(self.handle, &mut bytes);

            if ptr == std::ptr::null_mut() {
                return None
            }

            Some(ClientPacket::new(self, ptr as *mut u8, bytes as usize))
        }
    }

    pub fn disconnect(&mut self) {
        unsafe {
            netcode::netcode_client_disconnect(self.handle)
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            netcode::netcode_client_destroy(self.handle);
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
            std::slice::from_raw_parts(self.data, self.size)
        }
    }
}

impl<'a> Drop for ClientPacket<'a> {
    fn drop(&mut self) {
        unsafe {
            netcode::netcode_client_free_packet(self.client.handle, self.data as *mut std::os::raw::c_void);
        }
    }
}

pub struct ConnectToken {
    token: [u8; netcode::NETCODE_CONNECT_TOKEN_BYTES as usize]
}

impl ConnectToken {
    pub fn from_bytes<I>(bytes: I) -> ConnectToken where I: Iterator<Item=u8> {
        let mut token = [0; netcode::NETCODE_CONNECT_TOKEN_BYTES];

        for (i,b) in bytes.enumerate() {
            token[i] = b;
        }

        ConnectToken { token: token }
    }

    pub fn from_hosts<I>(hosts: I, private_key: &mut [u8; netcode::NETCODE_KEY_BYTES], expire: i32, client_id: u64, protocol: u64, sequence: u64)
            -> Result<ConnectToken, ClientError>
            where I: Iterator<Item=String> {
        let mut host_list_ptr = [std::ptr::null_mut(); netcode::NETCODE_MAX_SERVERS_PER_CONNECT];
        let mut host_count = 0;

        for (i,host) in hosts.enumerate().take(netcode::NETCODE_MAX_SERVERS_PER_CONNECT) {
            let cstr = CString::new(host).unwrap();
            host_list_ptr[i] = cstr.into_raw();
            host_count += 1;
        }

        let mut token = [0; netcode::NETCODE_CONNECT_TOKEN_BYTES];

        unsafe {
            match netcode::netcode_generate_connect_token(host_count,
                host_list_ptr.as_mut_ptr(),
                expire,
                client_id,
                protocol,
                sequence,
                private_key.as_mut_ptr(),
                token.as_mut_ptr()
                ) {
                    0 => Ok(ConnectToken { token: token }),
                    _ => Err(ClientError::Token)
            }
        }

    }
}

pub struct Server {
    handle: *mut netcode::netcode_server_t
}

impl Server {
}

impl Drop for Server {
    fn drop(&mut self) {
        unsafe {
            netcode::netcode_server_destroy(self.handle);
            util::global_term();
        }
    }
}