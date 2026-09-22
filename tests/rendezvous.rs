//! Rendezvous register/lookup.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ppose::rendezvous::{
    decode_reply, encode_lookup, encode_register, token_from_psk, RendezvousService,
};

#[test]
fn register_and_lookup() {
    let mut rs = RendezvousService::bind("127.0.0.1:0").unwrap();
    let rs_addr = rs.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let th = thread::spawn(move || {
        while !flag.load(Ordering::SeqCst) {
            let _ = rs.step();
        }
    });

    let token = token_from_psk(b"unit-psk", 1);
    let alice = UdpSocket::bind("127.0.0.1:0").unwrap();
    alice
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    alice.send_to(&encode_register(&token), rs_addr).unwrap();
    thread::sleep(Duration::from_millis(50));

    let bob = UdpSocket::bind("127.0.0.1:0").unwrap();
    bob.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    bob.send_to(&encode_lookup(&token), rs_addr).unwrap();
    let mut buf = [0u8; 512];
    let (n, _) = bob.recv_from(&mut buf).expect("reply");
    let got = decode_reply(&buf[..n]).expect("addr");
    assert_eq!(got, alice.local_addr().unwrap());

    stop.store(true, Ordering::SeqCst);
    th.join().unwrap();
}
