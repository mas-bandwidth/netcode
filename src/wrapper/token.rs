use wrapper::netcode::*;

use std::ffi::CString;

#[derive(Debug)]
pub enum TokenError {
    Generate
}

pub struct ConnectToken {
    token: [u8; NETCODE_CONNECT_TOKEN_BYTES as usize]
}

impl ConnectToken {
    pub fn from_bytes<I>(bytes: I) -> ConnectToken where I: Iterator<Item=u8> {
        let mut token = [0; NETCODE_CONNECT_TOKEN_BYTES];

        for (i,b) in bytes.enumerate().take(NETCODE_CONNECT_TOKEN_BYTES) {
            token[i] = b;
        }

        ConnectToken { token: token }
    }

    pub fn from_hosts<I>(hosts: I, private_key: &[u8; NETCODE_KEY_BYTES], expire: i32, client_id: u64, protocol: u64, sequence: u64)
            -> Result<ConnectToken, TokenError>
            where I: Iterator<Item=String> {
        let mut host_list_ptr = [::std::ptr::null_mut(); NETCODE_MAX_SERVERS_PER_CONNECT];
        let mut host_count = 0;

        for (i,host) in hosts.enumerate().take(NETCODE_MAX_SERVERS_PER_CONNECT) {
            let cstr = CString::new(host).unwrap();
            host_list_ptr[i] = cstr.into_raw();
            host_count += 1;
        }

        let mut token = [0; NETCODE_CONNECT_TOKEN_BYTES];

        let result = unsafe {
            match netcode_generate_connect_token(host_count,
                host_list_ptr.as_ptr() as *const *const i8,
                expire,
                client_id,
                protocol,
                sequence,
                private_key.as_ptr(),
                token.as_mut_ptr()
                ) {
                    0 => Err(TokenError::Generate),
                    _ => Ok(ConnectToken { token: token })
            }
        };

        //Make sure to free our memory that we passed to netcode
        for host in &mut host_list_ptr[..] {
            if *host != ::std::ptr::null_mut() {
                unsafe {
                    CString::from_raw(*host);
                }
            }
            *host = ::std::ptr::null_mut();
        }

        result
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.token
    }
}