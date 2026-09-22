//! IPv4 UDP forwarder with a bounded replay cache.
//!
//! This is not onion routing. The relay sees destination addresses.

use std::env;

use ppose::relay::Relay;

fn main() {
    let bind = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:0".into());
    let mut r = Relay::bind(&bind).expect("bind");
    println!("relay {}", r.local_addr().unwrap());
    loop {
        let _ = r.step();
    }
}
