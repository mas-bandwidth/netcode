use std::sync::atomic;

use netcode;

static mut NETCODE_INIT_COUNT: atomic::AtomicUsize = atomic::ATOMIC_USIZE_INIT;

pub fn global_init() {
    unsafe {
        NETCODE_INIT_COUNT.fetch_add(1, atomic::Ordering::SeqCst);
        netcode::netcode_init();
    }
}

pub fn global_term() {
    unsafe {
        let active = NETCODE_INIT_COUNT.fetch_sub(1, atomic::Ordering::SeqCst);
        if active == 0 {
            netcode::netcode_term();
        }
    }
}