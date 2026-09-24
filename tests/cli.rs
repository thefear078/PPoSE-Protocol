//! End-to-end tests of the real `ppose` binary: every transport mode the
//! library implements must also be usable from the CLI.

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ppose");

/// A running `ppose` process whose stdout lines are collected on a thread.
/// Killed on drop, so long-running relays/servers never outlive the test.
struct Proc {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Proc {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ppose");
        let (tx, lines) = channel();
        let stdout = child.stdout.take().unwrap();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    /// Rest of the first stdout line starting with `prefix`.
    fn wait_for(&mut self, prefix: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if let Some(rest) = line.strip_prefix(prefix) {
                        return rest.trim().to_string();
                    }
                }
                Err(_) => panic!("no `{prefix}` line; got {:?}", self.seen),
            }
        }
    }

    /// Wait for exit; returns (success, stderr).
    fn finish(mut self) -> (bool, String) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                let mut err = String::new();
                if let Some(mut s) = self.child.stderr.take() {
                    use std::io::Read;
                    let _ = s.read_to_string(&mut err);
                }
                return (status.success(), err);
            }
            assert!(Instant::now() < deadline, "process did not exit");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a listen/connect pair; assert both succeed and the messages arrive.
fn exchange(listen_args: &[&str], connect_args: &[&str], msg: &str) {
    let mut listen = Proc::spawn(listen_args);
    let listen_addr = listen.wait_for("listen ");
    let mut args: Vec<&str> = connect_args.to_vec();
    let peer_arg = listen_addr.clone();
    if !args.contains(&"--rs") {
        args.insert(1, &peer_arg);
    }
    args.extend(["--msg", msg]);
    let mut connect = Proc::spawn(&args);
    assert_eq!(connect.wait_for("recv "), "ack");
    assert_eq!(listen.wait_for("recv "), msg);
    let (ok, err) = connect.finish();
    assert!(ok, "connect failed: {err}");
    let (ok, err) = listen.finish();
    assert!(ok, "listen failed: {err}");
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn direct() {
    exchange(&["listen"], &["connect"], "hello-direct");
}

#[test]
fn via_relay() {
    let mut relay = Proc::spawn(&["relay"]);
    let relay_addr = relay.wait_for("relay ");
    exchange(
        &["listen", "--via-relay", &relay_addr],
        &["connect", "--via-relay", &relay_addr],
        "hello-relay",
    );
}

#[test]
fn two_onion_hops_multi_fragment_message() {
    let mut h1 = Proc::spawn(&["onion-relay"]);
    let mut h2 = Proc::spawn(&["onion-relay"]);
    let hop1 = h1.wait_for("hop ");
    let hop2 = h2.wait_for("hop ");
    // PND has no reply blocks, so the listener must know the connector's
    // address up front — pin it with --bind.
    let back = format!("127.0.0.1:{}", free_port());
    let big = "x".repeat(2000);
    exchange(
        &[
            "listen",
            "--return-hop",
            &hop2,
            "--return-hop",
            &hop1,
            "--return-dest",
            &back,
        ],
        &["connect", "--hop", &hop1, "--hop", &hop2, "--bind", &back],
        &big,
    );
}

#[test]
fn rendezvous_lookup() {
    let mut rs = Proc::spawn(&["rs"]);
    let rs_addr = rs.wait_for("rendezvous ");
    let mut listen = Proc::spawn(&["listen", "--rs", &rs_addr, "--psk", "cli-test"]);
    listen.wait_for("rs ");
    let mut connect = Proc::spawn(&[
        "connect", "--rs", &rs_addr, "--psk", "cli-test", "--msg", "hello-rs",
    ]);
    connect.wait_for("rs ");
    assert_eq!(connect.wait_for("recv "), "ack");
    assert_eq!(listen.wait_for("recv "), "hello-rs");
    assert!(connect.finish().0);
    assert!(listen.finish().0);
}

#[test]
fn cover_traffic_both_sides() {
    exchange(
        &["listen", "--cover", "stealth"],
        &["connect", "--cover", "balanced"],
        "hello-cover",
    );
}

#[test]
fn connect_to_nobody_fails_instead_of_hanging() {
    let port = free_port();
    let target = format!("127.0.0.1:{port}");
    let started = Instant::now();
    let (ok, _) = Proc::spawn(&["connect", &target]).finish();
    assert!(!ok);
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[test]
fn misspelled_flag_is_rejected() {
    let (ok, err) = Proc::spawn(&["connect", "127.0.0.1:9", "--covr", "stealth"]).finish();
    assert!(!ok);
    assert!(err.contains("unexpected argument --covr"), "stderr: {err}");
}

#[test]
fn non_ascii_hex_is_an_error_not_a_panic() {
    let (ok, err) = Proc::spawn(&["connect", "127.0.0.1:9", "--pin", &"é".repeat(32)]).finish();
    assert!(!ok);
    assert!(err.contains("hex"), "stderr: {err}");
    assert!(!err.contains("panicked"), "stderr: {err}");
}
