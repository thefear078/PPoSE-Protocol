//! Command-line entry.

use std::env;
use std::error::Error;
use std::net::{SocketAddr, UdpSocket};
use std::process;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use ppose::admission::Invitation;
use ppose::admission::InviteSigningKey;
use ppose::admission::InviteVerifyingKey;
use ppose::admission::TrustStore;
use ppose::cover::CoverMode;
use ppose::crypto::keys::IdentitySecret;
use ppose::crypto::keys::PublicIdentity;
use ppose::onion::{OnionHop, OnionRelay};
use ppose::relay::Relay;
use ppose::rendezvous::{
    decode_reply, encode_lookup, encode_register, token_from_psk, RendezvousService,
};
use ppose::session::{Path, UdpSession};
use ppose::CRATE_VERSION;

type CliResult<T> = Result<T, Box<dyn Error>>;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn run() -> CliResult<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    let mut rest: Vec<String> = args.collect();
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
        "invite" => invite(&mut rest),
        "listen" => listen(&mut rest),
        "connect" => connect(&mut rest),
        "relay" => {
            let bind = positional_or(&mut rest, "127.0.0.1:0")?;
            no_leftovers(&rest)?;
            let mut r = Relay::bind(&bind)?;
            println!("relay {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "onion-relay" => {
            let id = take_key_flag(&mut rest, "--key")?.unwrap_or_else(IdentitySecret::generate);
            let bind = positional_or(&mut rest, "127.0.0.1:0")?;
            no_leftovers(&rest)?;
            let mut r = OnionRelay::bind(&bind, id)?;
            let addr = r.local_addr()?;
            let public = hex(&r.public().as_bytes());
            println!("onion-relay {addr}");
            println!("public {public}");
            println!("hop {addr}={public}");
            loop {
                r.step()?;
            }
        }
        "rs" => {
            let bind = positional_or(&mut rest, "127.0.0.1:0")?;
            no_leftovers(&rest)?;
            let mut r = RendezvousService::bind(&bind)?;
            println!("rendezvous {}", r.local_addr()?);
            loop {
                r.step()?;
            }
        }
        "rs-register" => {
            let rs: SocketAddr = positional(&mut rest, "usage: ppose rs-register <rs> [psk]")?;
            let psk = positional_or(&mut rest, "demo")?;
            no_leftovers(&rest)?;
            let sock = bind_client(None, rs)?;
            let token = token_from_psk(psk.as_bytes(), rs_epoch_now());
            sock.send_to(&encode_register(&token), rs)?;
            println!("registered token {}", hex(&token));
            println!("local {}", sock.local_addr()?);
            Ok(())
        }
        "rs-lookup" => {
            let rs: SocketAddr = positional(&mut rest, "usage: ppose rs-lookup <rs> [psk]")?;
            let psk = positional_or(&mut rest, "demo")?;
            no_leftovers(&rest)?;
            let sock = bind_client(None, rs)?;
            match rs_lookup(&sock, rs, &psk)? {
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

fn invite(rest: &mut Vec<String>) -> CliResult<()> {
    let ttl = take_flag(rest, "--ttl-secs")?
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|_| "--ttl-secs must be a number")?
        .unwrap_or(86_400);
    let signer_hex = take_flag(rest, "--signer")?
        .ok_or("invite requires --signer <hex32 keygen-invite secret>")?;
    let subject_hex: String = positional(
        rest,
        "usage: ppose invite <subject hex32> --signer <hex32> [--ttl-secs N]",
    )?;
    no_leftovers(rest)?;
    let subject = PublicIdentity::from_bytes(parse_hex32(&subject_hex)?);
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

fn listen(rest: &mut Vec<String>) -> CliResult<()> {
    let pin = take_pin_flag(rest, "--pin")?;
    let id = take_key_flag(rest, "--key")?.unwrap_or_else(IdentitySecret::generate);
    let admit_roots = take_all_flag(rest, "--admit-root");
    let admit_invites = take_all_flag(rest, "--admit-invite");
    let admit_depth: u8 = take_flag(rest, "--admit-depth")?
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| "--admit-depth must be a number")?
        .unwrap_or(0);
    let via_relay = take_addr_flag(rest, "--via-relay")?;
    let return_hops = take_hops(rest, "--return-hop")?;
    let return_dest = take_addr_flag(rest, "--return-dest")?;
    let rs = take_addr_flag(rest, "--rs")?;
    let psk = take_flag(rest, "--psk")?.unwrap_or_else(|| "demo".into());
    let cover = take_cover_flag(rest)?;
    let bind = positional_or(rest, "127.0.0.1:0")?;
    no_leftovers(rest)?;
    if via_relay.is_some() && !return_hops.is_empty() {
        return Err("--via-relay and --return-hop are mutually exclusive".into());
    }
    if return_dest.is_some() && return_hops.is_empty() {
        return Err("--return-dest only applies together with --return-hop".into());
    }

    let sock = UdpSocket::bind(&bind)?;
    sock.set_read_timeout(Some(Duration::from_secs(30)))?;
    println!("listen {}", sock.local_addr()?);
    println!("fp {}", hex(&id.public().fingerprint()));
    if let Some(rs) = rs {
        // Registered from the listening socket itself, so the address the
        // rendezvous records is the one a peer can actually reach us on.
        let token = token_from_psk(psk.as_bytes(), rs_epoch_now());
        sock.send_to(&encode_register(&token), rs)?;
        println!("rs    registered at {rs} (entry lives 60 s)");
    }
    if pin.is_some() {
        println!("pin   expecting pinned remote static key");
    }
    let mut s = if return_hops.is_empty() {
        UdpSession::accept_responder_pinned(sock, &id, via_relay, pin)?
    } else {
        // PND has no reply blocks: the responder must be told the return
        // route and the connector's address up front.
        let dest = return_dest.ok_or("--return-hop needs --return-dest <connector addr>")?;
        let s = UdpSession::accept_responder_onion(sock, &id, return_hops, dest)?;
        if let Some(expected) = &pin {
            s.pin_remote(expected)?;
        }
        s
    };
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
            let reason = format!(
                "rejected: identity {} not admitted (Web-of-Trust gate, depth {admit_depth})",
                hex(&remote)
            );
            // The handshake already completed, so there is a working
            // authenticated channel — use it to tell the peer why instead of
            // leaving them with a bare connection reset. Best-effort: if this
            // send fails too, the error below still explains it on this end.
            let _ = s.send(reason.as_bytes());
            return Err(reason.into());
        }
        println!("admit remote identity is admitted");
    }
    s.set_cover(cover);
    let msg = s.recv(Duration::from_secs(30))?;
    println!("recv {}", String::from_utf8_lossy(&msg));
    s.send(b"ack")?;
    Ok(())
}

fn connect(rest: &mut Vec<String>) -> CliResult<()> {
    const USAGE: &str = "usage: ppose connect <peer> [options]  (or --rs <addr> instead of <peer>)";
    let pin = take_pin_flag(rest, "--pin")?;
    let id = take_key_flag(rest, "--key")?.unwrap_or_else(IdentitySecret::generate);
    let bind = take_flag(rest, "--bind")?;
    let via_relay = take_addr_flag(rest, "--via-relay")?;
    let hops = take_hops(rest, "--hop")?;
    let rs = take_addr_flag(rest, "--rs")?;
    let psk = take_flag(rest, "--psk")?.unwrap_or_else(|| "demo".into());
    let cover = take_cover_flag(rest)?;
    let msg = take_flag(rest, "--msg")?.unwrap_or_else(|| "hello".into());
    let explicit_peer: Option<SocketAddr> = if rest.is_empty() {
        None
    } else {
        Some(positional(rest, USAGE)?)
    };
    no_leftovers(rest)?;
    if via_relay.is_some() && !hops.is_empty() {
        return Err("--via-relay and --hop are mutually exclusive".into());
    }

    let first_contact = rs
        .or(via_relay)
        .or(hops.first().map(|h| h.addr))
        .or(explicit_peer)
        .ok_or(USAGE)?;
    let sock = bind_client(bind.as_deref(), first_contact)?;
    println!("local {}", sock.local_addr()?);
    let peer = match (explicit_peer, rs) {
        (Some(peer), _) => peer,
        (None, Some(rs)) => {
            let peer = rs_lookup(&sock, rs, &psk)?
                .ok_or("peer not registered at the rendezvous (or its 60 s entry expired)")?;
            println!("rs    found peer {peer}");
            peer
        }
        (None, None) => return Err(USAGE.into()),
    };
    let path = if let Some(relay) = via_relay {
        Path::ViaRelay { relay, peer }
    } else if !hops.is_empty() {
        Path::ViaOnion { hops, dest: peer }
    } else {
        Path::Direct { peer }
    };
    if pin.is_some() {
        println!("pin   expecting pinned remote static key");
    }
    let mut s = UdpSession::connect_initiator_pinned(sock, &id, path, pin)?;
    s.set_cover(cover);
    s.send(msg.as_bytes())?;
    let reply = s.recv(Duration::from_secs(10))?;
    println!("recv {}", String::from_utf8_lossy(&reply));
    Ok(())
}

fn print_help() {
    eprintln!(
        "ppose {CRATE_VERSION} — research prototype (not an anonymity network)\n\n\
         Commands:\n\
           keygen\n\
           keygen-invite\n\
           invite <subject hex32> --signer <hex32> [--ttl-secs N]\n\
           listen [bind] [--key H] [--pin H] [--cover MODE]\n\
             [--via-relay ADDR | --return-hop ADDR=H... --return-dest ADDR]\n\
             [--rs ADDR [--psk PSK]]\n\
             [--admit-root H]... [--admit-invite H288]... [--admit-depth N]\n\
           connect <peer> [--key H] [--pin H] [--cover MODE] [--bind ADDR]\n\
             [--via-relay ADDR | --hop ADDR=H...] [--msg TEXT]\n\
           connect --rs ADDR [--psk PSK] [...same options]\n\
           relay [bind]                   cleartext dest forwarder\n\
           onion-relay [bind] [--key H]   PND hop (not Sphinx)\n\
           rs [bind]                      token rendezvous\n\
           rs-register <rs> [psk]         register a throwaway socket (server test)\n\
           rs-lookup <rs> [psk]\n\
           version\n\n\
         H is 64 hex chars (32 bytes). ADDR is ip:port.\n\n\
         --key loads a persistent identity (a `keygen` \"secret\") instead of a\n\
         fresh random one each run — needed so a peer's --pin keeps working.\n\
         --pin requires the peer's Noise static key (their `keygen` \"public\"),\n\
         failing closed instead of trust-on-first-use.\n\
         --cover off|balanced|stealth sends idle cover datagrams (unmeasured\n\
         against real traffic; see docs/SPECIFICATION.md §8).\n\
         --bind sets connect's local address; by default it binds 0.0.0.0:0\n\
         so the OS picks a real route.\n\n\
         Paths (all relays see addresses; none of this is anonymous):\n\
         --via-relay ADDR goes through a `relay`; the listener passes the same\n\
         relay address so it only accepts traffic from it.\n\
         --hop ADDR=H (repeat, in order) goes through `onion-relay` hops; each\n\
         prints its own ready-to-paste `hop` line. PND has no reply blocks, so\n\
         the listener needs the reverse route (--return-hop, last hop first)\n\
         and the connector's address (--return-dest; pin it with --bind).\n\
         --rs ADDR registers the listener at a rendezvous under --psk (default\n\
         \"demo\"), and lets connect look the peer up instead of naming it.\n\
         The token rotates hourly; connect also tries the previous hour.\n\n\
         Admission (Invitation Web-of-Trust — a local policy gate, NOT a Sybil\n\
         defense): --admit-root trusts a `keygen-invite` public key; with none\n\
         given, listen accepts anyone. --admit-invite loads `invite` output so\n\
         chains up to --admit-depth hops resolve. Checked after the handshake,\n\
         on the peer's authenticated identity; rejected peers are told why.\n"
    );
}

/// Bind a client socket that can reach `target`: `--bind` if given, else an
/// ephemeral port on the unspecified address of `target`'s family so the OS
/// picks a real route (a loopback-bound socket can only reach localhost).
/// The read timeout bounds the handshake against a silent peer.
fn bind_client(explicit: Option<&str>, target: SocketAddr) -> CliResult<UdpSocket> {
    let bind = match explicit {
        Some(b) => b,
        None if target.is_ipv6() => "[::]:0",
        None => "0.0.0.0:0",
    };
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok(sock)
}

fn rs_epoch_now() -> u64 {
    unix_now() / 3600
}

/// Look `psk`'s token up at `rs` for this hour, then the previous one — a
/// registration made just before the hour turned stays live for up to its
/// 60 s TTL.
fn rs_lookup(sock: &UdpSocket, rs: SocketAddr, psk: &str) -> CliResult<Option<SocketAddr>> {
    let epoch = rs_epoch_now();
    for e in [epoch, epoch.saturating_sub(1)] {
        sock.send_to(&encode_lookup(&token_from_psk(psk.as_bytes(), e)), rs)?;
        let mut buf = [0u8; 512];
        for _ in 0..8 {
            let (n, from) = sock.recv_from(&mut buf)?;
            if from != rs {
                continue;
            }
            if let Some(addr) = decode_reply(&buf[..n]) {
                return Ok(Some(addr));
            }
            break;
        }
    }
    Ok(None)
}

/// `ADDR=H`, exactly the `hop` line `onion-relay` prints.
fn parse_hop(s: &str) -> CliResult<OnionHop> {
    let (addr, pk) = s
        .split_once('=')
        .ok_or_else(|| format!("hop must be <ip:port>=<public hex32>, got {s}"))?;
    Ok(OnionHop {
        addr: addr.parse()?,
        pk: PublicIdentity::from_bytes(parse_hex32(pk)?),
    })
}

fn take_hops(args: &mut Vec<String>, flag: &str) -> CliResult<Vec<OnionHop>> {
    take_all_flag(args, flag)
        .iter()
        .map(|h| parse_hop(h))
        .collect()
}

fn take_cover_flag(args: &mut Vec<String>) -> CliResult<CoverMode> {
    match take_flag(args, "--cover")?.as_deref() {
        None | Some("off") => Ok(CoverMode::Off),
        Some("balanced") => Ok(CoverMode::Balanced),
        Some("stealth") => Ok(CoverMode::Stealth),
        Some(other) => {
            Err(format!("--cover must be off, balanced, or stealth; got {other}").into())
        }
    }
}

fn take_addr_flag(args: &mut Vec<String>, flag: &str) -> CliResult<Option<SocketAddr>> {
    take_flag(args, flag)?
        .map(|v| v.parse().map_err(|e| format!("{flag} {v}: {e}").into()))
        .transpose()
}

/// Remove a `--pin <hex32>` flag from `args` (if present) and parse it into
/// the identity a peer must present at handshake time.
fn take_pin_flag(args: &mut Vec<String>, flag: &str) -> CliResult<Option<PublicIdentity>> {
    take_flag(args, flag)?
        .map(|v| parse_hex32(&v).map(PublicIdentity::from_bytes))
        .transpose()
}

/// Remove a `--key <hex32>` flag from `args` (if present) and parse it into
/// a persistent local identity secret.
fn take_key_flag(args: &mut Vec<String>, flag: &str) -> CliResult<Option<IdentitySecret>> {
    take_flag(args, flag)?
        .map(|v| parse_hex32(&v).map(IdentitySecret::from_bytes))
        .transpose()
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> CliResult<Option<String>> {
    let Some(pos) = args.iter().position(|a| a == flag) else {
        return Ok(None);
    };
    if pos + 1 >= args.len() {
        return Err(format!("{flag} requires a value").into());
    }
    args.remove(pos);
    Ok(Some(args.remove(pos)))
}

/// Remove every `flag <value>` pair from `args`, in the order encountered. A
/// trailing `flag` with no value is left in place for [`no_leftovers`].
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

/// Take the next positional argument (call after all flags are taken).
fn positional<T: std::str::FromStr>(args: &mut Vec<String>, usage: &str) -> CliResult<T>
where
    T::Err: Error + 'static,
{
    if args.is_empty() {
        return Err(usage.into());
    }
    Ok(args.remove(0).parse()?)
}

fn positional_or(args: &mut Vec<String>, default: &str) -> CliResult<String> {
    if args.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(args.remove(0))
    }
}

/// Reject anything not consumed — a misspelled flag would otherwise be
/// silently ignored or mistaken for an address.
fn no_leftovers(args: &[String]) -> CliResult<()> {
    match args.first() {
        None => Ok(()),
        Some(extra) => Err(format!("unexpected argument {extra}").into()),
    }
}

fn parse_hex32(s: &str) -> CliResult<[u8; 32]> {
    let bytes = parse_hex(s)?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes (64 hex chars), got {}", v.len()).into())
}

fn parse_hex(s: &str) -> CliResult<Vec<u8>> {
    // Validate first: slicing a string with non-ASCII characters at byte
    // offsets would panic instead of reporting a bad argument.
    if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected only hex characters (0-9, a-f)".into());
    }
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
