use netcode;
use util;

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