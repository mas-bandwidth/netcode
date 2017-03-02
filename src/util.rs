use std::sync::atomic;

use netcode;

static mut netcode_init_count: atomic::AtomicUsize = atomic::ATOMIC_USIZE_INIT;

pub fn global_init() {
    unsafe {
        netcode_init_count.fetch_add(1, atomic::Ordering::SeqCst);
        netcode::netcode_init();
    }
}

pub fn global_term() {
    unsafe {
        let active = netcode_init_count.fetch_sub(1, atomic::Ordering::SeqCst);
        if active == 0 {
            netcode::netcode_term();
        }
    }
}