use std::sync::atomic;

use netcode;

static mut NETCODE_INIT_COUNT: atomic::AtomicUsize = atomic::ATOMIC_USIZE_INIT;

pub fn global_init() {
    unsafe {
        if NETCODE_INIT_COUNT.fetch_add(1, atomic::Ordering::SeqCst) == 1 {
            netcode::netcode_init();
        }
    }
}

pub fn global_term() {
    unsafe {
        if NETCODE_INIT_COUNT.fetch_sub(1, atomic::Ordering::SeqCst) == 0 {
            netcode::netcode_term();
        }
    }
}