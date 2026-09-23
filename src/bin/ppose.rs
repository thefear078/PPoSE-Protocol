//! Command-line entry.

use std::env;
use std::net::UdpSocket;
use std::process;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use ppose::admission::Invitation;
use ppose::admission::InviteSigningKey;
use ppose::admission::InviteVerifyingKey;
use ppose::admission::TrustStore;
use ppose::crypto::keys::IdentitySecret;
use ppose::crypto::keys::PublicIdentity;
use ppose::network::udp::bind_loopback;
use ppose::onion::OnionRelay;
use ppose::relay::Relay;
use ppose::rendezvous::{
    decode_reply, encode_lookup, encode_register, token_from_psk, RendezvousService,
};
use ppose::session::{Path, UdpSession};
use ppose::CRATE_VERSION;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "version" | "-V" => {
            println!("ppose {CRATE_VERSION}");
            Ok(())
        }
        "keygen" => {
            let sk = IdentitySecret::generate();
            println!("secret  {}", hex(&sk.to_bytes()));
            println!("public  {}", hex(&sk.public().as_bytes()));
            println!("fp      {}", hex(&sk.public().fingerprint()));
            Ok(())
        }
        "keygen-invite" => {
            let sk = InviteSigningKey::generate();
            println!("secret  {}", hex(&sk.to_bytes()));
            println!("public  {}", hex(&sk.public().as_bytes()));
            Ok(())
        }
        "invite" => {
            let mut rest: Vec<String> = args.collect();
            let ttl = take_flag(&mut rest, "--ttl-secs")?
                .map(|v| v.parse::<u64>())
                .transpose()
                .map_err(|_| "--ttl-secs must be a number")?
                .unwrap_or(86_400);
            let signer_hex = take_flag(&mut rest, "--signer")?
                .ok_or("invite requires --signer <hex32 keygen-invite secret>")?;
            if rest.is_empty() {
                return Err(
                    "usage: ppose invite <subject hex32> --signer <hex32> [--ttl-secs N]".into(),
                );
            }
            let subject = PublicIdentity::from_bytes(parse_hex32(&rest.remove(0))?);
            let signer = InviteSigningKey::from_bytes(parse_hex32(&signer_hex)?);
            let now = unix_now();
            let invite = signer.issue(&subject, now, ttl);
            println!("root     {}", hex(&signer.public().as_bytes()));
            println!("subject  {}", hex(&subject.as_bytes()));
            println!("issued   {now}");
            println!("expires  {}", now + ttl);
            println!("invite   {}", hex(&invite.encode()));
            Ok(())
        }
        "listen" => {
            let mut rest: Vec<String> = args.collect();
            let pin = take_pin_flag(&mut rest, "--pin")?;
            let id = take_key_flag(&mut rest, "--key")?.unwrap_or_else(IdentitySecret::generate);
            let admit_roots = take_all_flag(&mut rest, "--admit-root");
            let admit_invites = take_all_flag(&mut rest, "--admit-invite");
            let admit_depth: u8 = take_flag(&mut rest, "--admit-depth")?
                .map(|v| v.parse())
                .transpose()
                .map_err(|_| "--admit-depth must be a number")?
                .unwrap_or(0);
            let bind = if rest.is_empty() {
                "127.0.0.1:0".to_string()
            } else {
                rest.remove(0)
            };
            let sock = UdpSocket::bind(&bind)?;
            sock.set_read_timeout(Some(Duration::from_secs(30)))?;
            println!("listen {}", sock.local_addr()?);
            println!("fp {}", hex(&id.public().fingerprint()));
            if pin.is_some() {
                println!("pin   expecting pinned remote static key");
            }
            let mut s = UdpSession::accept_responder_pinned(sock, &id, None, pin)?;
            if !admit_roots.is_empty() {
                let mut store = TrustStore::new();
                for r in &admit_roots {
                    store.add_root(InviteVerifyingKey::from_bytes(parse_hex32(r)?)?);
                }
                let now = unix_now();
                for inv in &admit_invites {
                    store.ingest(Invitation::decode(&parse_hex(inv)?)?, now)?;
                }
                let remote = s.remote_static()?;
                if !store.is_admitted(&remote, admit_depth, now) {
                    return Err(format!(
                        "remote identity {} not admitted (Web-of-Trust gate, depth {admit_depth})",
                        hex(&remote)
                    )
                    .into());
                }
                println!("admit remote identity is admitted");
            }
            let msg = s.recv(Duration::from_secs(30))?;
            println!("recv {}", String::from_utf8_lossy(&msg));
            s.send(b"ack")?;
            Ok(())
        }
        "connect" => {
            let mut rest: Vec<String> = args.collect();
            let pin = take_pin_flag(&mut rest, "--pin")?;
            let id = take_key_flag(&mut rest, "--key")?.unwrap_or_else(IdentitySecret::generate);
            if rest.is_empty() {
                return Err("usage: ppose connect <peer> [--pin <hex32>] [--key <hex32>]".into());
            }
            let peer: std::net::SocketAddr = rest.remove(0).parse()?;
            let (sock, addr) = bind_loopback()?;
            println!("local {addr}");
            if pin.is_some() {
                println!("pin   expecting pinned remote static key");
            }
            let mut s =
                UdpSession::connect_initiator_pinned(sock, &id, Path::Direct { peer }, pin)?;
            s.send(b"hello")?;
            let reply = s.recv(Duration::from_secs(10))?;
            println!("recv {}", String::from_utf8_lossy(&reply));
            Ok(())
        }
        "relay" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let mut r = Relay::bind(&bind)?;
            println!("relay {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "onion-relay" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let id = IdentitySecret::generate();
            let mut r = OnionRelay::bind(&bind, id)?;
            println!("onion-relay {}", r.local_addr()?);
            println!("public {}", hex(&r.public().as_bytes()));
            loop {
                r.step()?;
            }
        }
        "rs" => {
            let bind = args.next().unwrap_or_else(|| "127.0.0.1:0".into());
            let mut r = RendezvousService::bind(&bind)?;
            println!("rendezvous {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "rs-register" => {
            let rs: std::net::SocketAddr = args.next().ok_or("rs-register <rs> <psk>")?.parse()?;
            let psk = args.next().unwrap_or_else(|| "demo".into());
            let token = token_from_psk(psk.as_bytes(), 0);
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            sock.send_to(&encode_register(&token), rs)?;
            println!("registered token {}", hex(&token));
            println!("local {}", sock.local_addr()?);
            Ok(())
        }
        "rs-lookup" => {
            let rs: std::net::SocketAddr = args.next().ok_or("rs-lookup <rs> <psk>")?.parse()?;
            let psk = args.next().unwrap_or_else(|| "demo".into());
            let token = token_from_psk(psk.as_bytes(), 0);
            let sock = UdpSocket::bind("127.0.0.1:0")?;
            sock.set_read_timeout(Some(Duration::from_secs(2)))?;
            sock.send_to(&encode_lookup(&token), rs)?;
            let mut buf = [0u8; 512];
            let (n, _) = sock.recv_from(&mut buf)?;
            match decode_reply(&buf[..n]) {
                Some(addr) => println!("peer {addr}"),
                None => println!("not found"),
            }
            Ok(())
        }
        other => {
            eprintln!("unknown command {other}");
            print_help();
            process::exit(2);
        }
    }
}

fn print_help() {
    eprintln!(
        "ppose {CRATE_VERSION} — research prototype (not an anonymity network)\n\n\
         Commands:\n\
           keygen\n\
           keygen-invite\n\
           invite <subject hex32> --signer <hex32> [--ttl-secs N]\n\
           listen [bind] [--pin <hex32>] [--key <hex32>]\n\
             [--admit-root <hex32>]... [--admit-invite <hex288>]... [--admit-depth N]\n\
           connect <peer> [--pin <hex32>] [--key <hex32>]\n\
           relay [bind]              cleartext dest forwarder\n\
           onion-relay [bind]        PND hop (not Sphinx)\n\
           rs [bind]                 token rendezvous\n\
           rs-register <rs> [psk]\n\
           rs-lookup <rs> [psk]\n\
           version\n\n\
         --pin pins the expected remote Noise static public key (64 hex\n\
         chars, from the peer's `keygen` \"public\" line) so the handshake\n\
         fails closed on an unexpected key instead of trust-on-first-use.\n\
         --key loads a persistent local identity (64 hex chars, from this\n\
         node's own `keygen` \"secret\" line) instead of a fresh random one\n\
         each run — needed so a peer's --pin stays valid across restarts.\n\n\
         Admission (Invitation Web-of-Trust, src/admission.rs — a local\n\
         policy gate, NOT a Sybil defense; see docs/SECURITY_REVIEW.md):\n\
         --admit-root registers a trusted `keygen-invite` public key\n\
         (repeatable). With no --admit-root given, listen accepts anyone,\n\
         same as before. --admit-invite loads an `invite`-command output\n\
         (repeatable) so chains longer than --admit-depth 0 can resolve.\n\
         A connecting peer whose Noise static identity isn't reachable\n\
         from a trusted root within --admit-depth hops is rejected after\n\
         the handshake completes (their identity is already authenticated\n\
         at that point — this only decides admission, not authenticity).\n"
    );
}

/// Remove a `--pin <hex32>` flag from `args` (if present) and parse it into
/// the identity a peer must present at handshake time.
///
/// # Errors
/// Returns an error if the flag is given without a value or the value is
/// not 64 hex characters encoding 32 bytes.
fn take_pin_flag(
    args: &mut Vec<String>,
    flag: &str,
) -> Result<Option<PublicIdentity>, Box<dyn std::error::Error>> {
    take_flag(args, flag)?
        .map(|v| parse_hex32(&v).map(PublicIdentity::from_bytes))
        .transpose()
}

/// Remove a `--key <hex32>` flag from `args` (if present) and parse it into
/// a persistent local identity secret.
///
/// # Errors
/// Returns an error if the flag is given without a value or the value is
/// not 64 hex characters encoding 32 bytes.
fn take_key_flag(
    args: &mut Vec<String>,
    flag: &str,
) -> Result<Option<IdentitySecret>, Box<dyn std::error::Error>> {
    take_flag(args, flag)?
        .map(|v| parse_hex32(&v).map(IdentitySecret::from_bytes))
        .transpose()
}

fn take_flag(
    args: &mut Vec<String>,
    flag: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(pos) = args.iter().position(|a| a == flag) else {
        return Ok(None);
    };
    if pos + 1 >= args.len() {
        return Err(format!("{flag} requires a value").into());
    }
    args.remove(pos);
    Ok(Some(args.remove(pos)))
}

/// Remove every `flag <value>` pair from `args`, in the order encountered.
/// Unlike [`take_flag`] this never errors: a trailing `flag` with no value
/// is simply left in `args` for the caller's own "unexpected argument"
/// handling (none of the current commands have one, so it's effectively
/// ignored — acceptable for this CLI's scope).
fn take_all_flag(args: &mut Vec<String>, flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag && i + 1 < args.len() {
            args.remove(i);
            out.push(args.remove(i));
        } else {
            i += 1;
        }
    }
    out
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = parse_hex(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes (64 hex chars), got {}", v.len()).into())
}

fn parse_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() % 2 != 0 {
        return Err(format!("expected an even number of hex chars, got {}", s.len()).into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
