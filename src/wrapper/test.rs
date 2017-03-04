use netcode::*;

use token::*;
use client::*;
use server::*;

const PRIVATE_KEY: [u8; NETCODE_KEY_BYTES] = [0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 
                                                  0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4, 
                                                  0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                  0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1];

const CONNECT_TOKEN_EXPIRY: i32 = 30;
const PROTOCOL_ID: u64 = 0x1122334455667788;
const CLIENT_ID: u64 = 0x8877665544332211;

fn gen_token() -> Result<ConnectToken, TokenError> {
    ConnectToken::from_hosts(["127.0.0.1:52345".to_string()].iter().cloned(), &PRIVATE_KEY, CONNECT_TOKEN_EXPIRY, CLIENT_ID, PROTOCOL_ID, 0)
}

#[test]
fn create_token() {
    assert!(gen_token().is_ok());
}

#[test]
fn create_client() {
    let token = gen_token().unwrap();

    {
        assert!(Client::new(&token).is_ok());
    }

    {
        assert!(Client::new_with_host("127.0.0.1:52345", &token).is_ok());
    }
}

#[test]
fn create_server() {
    assert!(Server::new("127.0.0.1:52345", "127.0.0.1:52345", &PRIVATE_KEY, PROTOCOL_ID, NETCODE_MAX_CLIENTS).is_ok());
}

#[test]
fn connect() {
    let mut client = Client::new(&(gen_token().unwrap())).unwrap();
    let mut server = Server::new("127.0.0.1:52345", "127.0.0.1:52345", &PRIVATE_KEY, PROTOCOL_ID, NETCODE_MAX_CLIENTS).unwrap();

    client.update(0.0);
    server.update(0.0);
    client.update(0.0);

    assert_eq!(client.state(), ClientState::Connected);
}