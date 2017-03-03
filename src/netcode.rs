pub const NETCODE_CONNECT_TOKEN_BYTES: usize = 4096;
pub const NETCODE_KEY_BYTES: usize = 32;
pub const NETCODE_MAX_SERVERS_PER_CONNECT: usize = 16;

pub const NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED: ::std::os::raw::c_int =
    -6;
pub const NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN: ::std::os::raw::c_int =
    -5;
pub const NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT: ::std::os::raw::c_int =
    -4;
pub const NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMEOUT:
          ::std::os::raw::c_int =
    -3;
pub const NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMEOUT:
          ::std::os::raw::c_int =
    -2;
pub const NETCODE_CLIENT_STATE_CONNECTION_DENIED: ::std::os::raw::c_int = -1;
pub const NETCODE_CLIENT_STATE_DISCONNECTED: ::std::os::raw::c_int = 0;
pub const NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
          ::std::os::raw::c_int =
    1;
pub const NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
          ::std::os::raw::c_int =
    2;
pub const NETCODE_CLIENT_STATE_CONNECTED: ::std::os::raw::c_int = 3;

pub const NETCODE_SOCKET_IPV6: ::std::os::raw::c_uint = 1;
pub const NETCODE_SOCKET_IPV4: ::std::os::raw::c_uint = 2;

pub const NETCODE_MAX_CLIENTS: usize = 256;
pub const NETCODE_MAX_PACKET_SIZE: usize = 1200;

pub const NETCODE_LOG_LEVEL_NONE: ::std::os::raw::c_uint = 0;
pub const NETCODE_LOG_LEVEL_INFO: ::std::os::raw::c_uint = 1;
pub const NETCODE_LOG_LEVEL_ERROR: ::std::os::raw::c_uint = 2;
pub const NETCODE_LOG_LEVEL_DEBUG: ::std::os::raw::c_uint = 3;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct netcode_client_t([u8; 0]);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct netcode_server_t([u8; 0]);

extern "C" {
    pub fn netcode_init() -> ::std::os::raw::c_int;
    pub fn netcode_term();
    pub fn netcode_log_level(level: ::std::os::raw::c_int);
    pub fn netcode_random_bytes(data: *mut u8, bytes: ::std::os::raw::c_int);

    pub fn netcode_client_create(address: *const ::std::os::raw::c_char,
                                 time: f64) -> *mut netcode_client_t;
    pub fn netcode_client_destroy(client: *mut netcode_client_t);
    pub fn netcode_client_connect(client: *mut netcode_client_t,
                                  connect_token: *const u8);
    pub fn netcode_client_update(client: *mut netcode_client_t, time: f64);
    pub fn netcode_client_send_packet(client: *mut netcode_client_t,
                                      packet_data: *const u8,
                                      packet_bytes: ::std::os::raw::c_int);
    pub fn netcode_client_receive_packet(client: *mut netcode_client_t,
                                         packet_bytes:
                                             *mut ::std::os::raw::c_int)
     -> *mut ::std::os::raw::c_void;
    pub fn netcode_client_free_packet(client: *mut netcode_client_t,
                                      packet: *mut ::std::os::raw::c_void);
    pub fn netcode_client_disconnect(client: *mut netcode_client_t);
    pub fn netcode_client_state(client: *const netcode_client_t)
     -> ::std::os::raw::c_int;
    pub fn netcode_client_index(client: *mut netcode_client_t)
     -> ::std::os::raw::c_int;
    pub fn netcode_generate_connect_token(num_server_addresses:
                                              ::std::os::raw::c_int,
                                          server_addresses:
                                              *const *const ::std::os::raw::c_char,
                                          expire_seconds:
                                              ::std::os::raw::c_int,
                                          client_id: u64, protocol_id: u64,
                                          sequence: u64, private_key: *const u8,
                                          connect_token: *mut u8)
     -> ::std::os::raw::c_int;

    pub fn netcode_server_create(bind_address: *const ::std::os::raw::c_char,
                                 public_address: *const ::std::os::raw::c_char,
                                 protocol_id: u64, private_key: *const u8,
                                 time: f64) -> *mut netcode_server_t;
    pub fn netcode_server_start(server: *mut netcode_server_t,
                                max_clients: ::std::os::raw::c_int);
    pub fn netcode_server_update(client: *mut netcode_server_t, time: f64);
    pub fn netcode_server_client_connected(server: *mut netcode_server_t,
                                           client_index:
                                               ::std::os::raw::c_int)
     -> ::std::os::raw::c_int;
    pub fn netcode_server_disconnect_client(server: *mut netcode_server_t,
                                            client_index:
                                                ::std::os::raw::c_int);
    pub fn netcode_server_disconnect_all_clients(server:
                                                     *mut netcode_server_t);
    pub fn netcode_server_send_packet(server: *mut netcode_server_t,
                                      client_index: ::std::os::raw::c_int,
                                      packet_data: *const u8,
                                      packet_bytes: ::std::os::raw::c_int);
    pub fn netcode_server_receive_packet(server: *mut netcode_server_t,
                                         client_index: ::std::os::raw::c_int,
                                         packet_bytes:
                                             *mut ::std::os::raw::c_int)
     -> *mut ::std::os::raw::c_void;
    pub fn netcode_server_free_packet(server: *mut netcode_server_t,
                                      packet: *mut ::std::os::raw::c_void);
    pub fn netcode_server_num_clients_connected(server: *mut netcode_server_t)
     -> ::std::os::raw::c_int;
    pub fn netcode_server_destroy(server: *mut netcode_server_t);
}