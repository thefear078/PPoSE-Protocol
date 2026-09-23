//! Invitation Web-of-Trust admission walkthrough.
//!
//! Not a Sybil defense — see `src/admission.rs` module docs.

use ppose::admission::InviteSigningKey;
use ppose::admission::TrustStore;
use ppose::crypto::keys::IdentitySecret;
use ppose::crypto::keys::PublicIdentity;

fn main() {
    let now = 1_700_000_000;

    // A bootstrap operator's admission identity: this node trusts it directly.
    let root = InviteSigningKey::generate();
    let mut store = TrustStore::new();
    store.add_root(root.public());
    store.set_max_invitees_per_issuer(50);

    // The root vouches for Alice's own admission identity, letting her
    // vouch for others in turn.
    let alice_signing = InviteSigningKey::generate();
    let alice_as_subject = PublicIdentity::from_bytes(alice_signing.public().as_bytes());
    let root_to_alice = root.issue(&alice_as_subject, now, 30 * 24 * 3600);
    store.ingest(root_to_alice, now).expect("root invite valid");

    // Alice vouches for Bob's PPoSE (Noise) identity.
    let bob = IdentitySecret::generate().public();
    let alice_to_bob = alice_signing.issue(&bob, now, 7 * 24 * 3600);
    store.ingest(alice_to_bob, now).expect("alice invite valid");

    let bob_bytes = bob.as_bytes();
    match store.trust_depth(&bob_bytes, 2, now) {
        Some(depth) => println!("bob admitted, {depth} hop(s) from a trusted root"),
        None => println!("bob NOT admitted"),
    }

    // A stranger nobody vouched for is correctly rejected.
    let mallory = IdentitySecret::generate().public();
    let mallory_bytes = mallory.as_bytes();
    println!(
        "mallory admitted: {}",
        store.is_admitted(&mallory_bytes, 2, now)
    );
}
