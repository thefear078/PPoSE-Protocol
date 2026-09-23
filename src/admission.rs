//! Invitation Web-of-Trust admission (Section 7 of the spec, formerly a sketch).
//!
//! An issuer holding an [`InviteSigningKey`] can vouch for a peer's PPoSE
//! (X25519) identity by issuing a signed, time-bounded [`Invitation`]. A
//! [`TrustStore`] anchored at one or more trusted roots walks chains of
//! invitations to decide whether an unknown identity should be admitted —
//! e.g. allowed to register with a rendezvous service or connect through a
//! relay.
//!
//! # Honest limits (see `docs/THREAT_MODEL.md`, "Sybil operator")
//!
//! This is **not** a cryptographic Sybil defense. A signature only proves
//! an issuer chose to vouch for a subject key; nothing stops an admitted
//! issuer from generating many subject keypairs and vouching for all of
//! them. [`TrustStore::set_max_invitees_per_issuer`] caps how many
//! *distinct* subjects one local store will admit through a single issuer,
//! which limits — but does not solve — that farming from the point of view
//! of one node. It is not enforced across the network, and soft trust
//! scores built on top of this can still be farmed, exactly as
//! `docs/SPECIFICATION.md` §7 already warns.

use std::collections::HashMap;
use std::collections::HashSet;

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use rand_core::OsRng;
use thiserror::Error;

use crate::crypto::keys::PublicIdentity;

/// Wire length of an encoded [`Invitation`]: issuer(32) + subject(32) + issued_at(8) + expires_at(8) + signature(64).
pub const INVITATION_LEN: usize = 32 + 32 + 8 + 8 + 64;

const DOMAIN: &[u8] = b"ppose-invite-v1";

/// Errors issuing, verifying, decoding, or admitting an [`Invitation`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// The Ed25519 signature does not verify over the invitation fields.
    #[error("invitation signature does not verify")]
    BadSignature,
    /// The byte slice is not a well-formed encoded invitation or key.
    #[error("invalid invitation encoding")]
    BadEncoding,
    /// `now` is before the invitation's `issued_at`.
    #[error("invitation is not yet valid")]
    NotYetValid,
    /// `now` is at or after the invitation's `expires_at`.
    #[error("invitation has expired")]
    Expired,
    /// The issuer has already vouched for `max_invitees_per_issuer` distinct
    /// subjects in this local store.
    #[error("issuer has reached its admitted-subject cap on this store")]
    IssuerCapReached,
}

fn signing_payload(
    issuer: &[u8; 32],
    subject: &[u8; 32],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN.len() + 32 + 32 + 8 + 8);
    buf.extend_from_slice(DOMAIN);
    buf.extend_from_slice(issuer);
    buf.extend_from_slice(subject);
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf.extend_from_slice(&expires_at.to_be_bytes());
    buf
}

/// Ed25519 signing identity used to issue invitations.
///
/// Kept separate from the X25519 Noise identity in [`crate::crypto::keys`]
/// on purpose: it is a distinct key for a distinct purpose (signing, not
/// key exchange), so a mistake with one does not weaken the other.
pub struct InviteSigningKey {
    key: SigningKey,
}

impl InviteSigningKey {
    /// Generate a fresh signing identity.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Construct from a raw 32-byte seed.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Raw seed bytes (handle with care).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Corresponding public verifying key.
    #[must_use]
    pub fn public(&self) -> InviteVerifyingKey {
        InviteVerifyingKey {
            key: self.key.verifying_key(),
        }
    }

    /// Vouch for `subject`'s PPoSE identity, valid from `now` for `ttl_secs`
    /// (both in unix seconds).
    #[must_use]
    pub fn issue(&self, subject: &PublicIdentity, now: u64, ttl_secs: u64) -> Invitation {
        let issuer = self.public();
        let issuer_bytes = issuer.as_bytes();
        let subject_bytes = subject.as_bytes();
        let issued_at = now;
        let expires_at = now.saturating_add(ttl_secs);
        let payload = signing_payload(&issuer_bytes, &subject_bytes, issued_at, expires_at);
        let signature = self.key.sign(&payload);
        Invitation {
            issuer,
            subject: subject_bytes,
            issued_at,
            expires_at,
            signature: signature.to_bytes(),
        }
    }
}

/// Ed25519 public verifying key for an invitation issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InviteVerifyingKey {
    key: VerifyingKey,
}

impl InviteVerifyingKey {
    /// Parse from raw 32 bytes.
    ///
    /// # Errors
    /// Returns [`AdmissionError::BadEncoding`] if the bytes are not a valid
    /// compressed Edwards point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AdmissionError> {
        VerifyingKey::from_bytes(&bytes)
            .map(|key| Self { key })
            .map_err(|_| AdmissionError::BadEncoding)
    }

    /// Raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// A signed, time-bounded vouch: `issuer` claims `subject` should be trusted.
#[derive(Clone, Debug)]
pub struct Invitation {
    issuer: InviteVerifyingKey,
    subject: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    signature: [u8; 64],
}

impl Invitation {
    /// Verify the signature and the `[issued_at, expires_at)` window against
    /// `now` (unix seconds).
    ///
    /// # Errors
    /// Returns [`AdmissionError::NotYetValid`], [`AdmissionError::Expired`],
    /// or [`AdmissionError::BadSignature`].
    pub fn verify(&self, now: u64) -> Result<(), AdmissionError> {
        if !self.time_valid(now) {
            return Err(if now < self.issued_at {
                AdmissionError::NotYetValid
            } else {
                AdmissionError::Expired
            });
        }
        let issuer_bytes = self.issuer.as_bytes();
        let payload = signing_payload(
            &issuer_bytes,
            &self.subject,
            self.issued_at,
            self.expires_at,
        );
        let sig = Signature::from_bytes(&self.signature);
        self.issuer
            .key
            .verify(&payload, &sig)
            .map_err(|_| AdmissionError::BadSignature)
    }

    /// Cheap `[issued_at, expires_at)` window check with **no signature
    /// verification**. Only safe to rely on for an invitation whose
    /// signature was already checked once (e.g. anything that went through
    /// [`TrustStore::ingest`], which calls [`verify`](Self::verify) before
    /// storing it — `Invitation`'s fields are otherwise immutable after
    /// that point).
    fn time_valid(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    /// Issuer that vouched for [`subject`](Self::subject).
    #[must_use]
    pub fn issuer(&self) -> InviteVerifyingKey {
        self.issuer
    }

    /// X25519 identity bytes being vouched for.
    #[must_use]
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }

    /// Encode to the fixed-length wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; INVITATION_LEN] {
        let mut out = [0u8; INVITATION_LEN];
        out[0..32].copy_from_slice(&self.issuer.as_bytes());
        out[32..64].copy_from_slice(&self.subject);
        out[64..72].copy_from_slice(&self.issued_at.to_be_bytes());
        out[72..80].copy_from_slice(&self.expires_at.to_be_bytes());
        out[80..144].copy_from_slice(&self.signature);
        out
    }

    /// Decode from the fixed-length wire form produced by [`encode`](Self::encode).
    ///
    /// This only parses the fields; call [`verify`](Self::verify) to check
    /// the signature and expiry before trusting the result.
    ///
    /// # Errors
    /// Returns [`AdmissionError::BadEncoding`] if `bytes` is the wrong
    /// length or the issuer key is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() != INVITATION_LEN {
            return Err(AdmissionError::BadEncoding);
        }
        let mut issuer_bytes = [0u8; 32];
        issuer_bytes.copy_from_slice(&bytes[0..32]);
        let mut subject = [0u8; 32];
        subject.copy_from_slice(&bytes[32..64]);
        let mut issued_at_b = [0u8; 8];
        issued_at_b.copy_from_slice(&bytes[64..72]);
        let mut expires_at_b = [0u8; 8];
        expires_at_b.copy_from_slice(&bytes[72..80]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[80..144]);
        Ok(Self {
            issuer: InviteVerifyingKey::from_bytes(issuer_bytes)?,
            subject,
            issued_at: u64::from_be_bytes(issued_at_b),
            expires_at: u64::from_be_bytes(expires_at_b),
            signature,
        })
    }
}

/// Local admission policy: trusted roots plus received invitations.
///
/// See the [module docs](self) for what this does and does not guarantee.
pub struct TrustStore {
    roots: HashSet<[u8; 32]>,
    /// issuer pubkey -> (subject pubkey -> invitation)
    edges: HashMap<[u8; 32], HashMap<[u8; 32], Invitation>>,
    max_invitees_per_issuer: usize,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustStore {
    /// Empty store with no trusted roots and no per-issuer cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            roots: HashSet::new(),
            edges: HashMap::new(),
            max_invitees_per_issuer: usize::MAX,
        }
    }

    /// Trust `root` directly — invitations it issues need no further vouching.
    pub fn add_root(&mut self, root: InviteVerifyingKey) {
        self.roots.insert(root.as_bytes());
    }

    /// Cap how many distinct subjects a single issuer may have admitted
    /// into this store at once. See the [module docs](self) for why this is
    /// a local mitigation, not a network-wide Sybil defense.
    pub fn set_max_invitees_per_issuer(&mut self, max: usize) {
        self.max_invitees_per_issuer = max;
    }

    /// Verify and add an invitation to the store.
    ///
    /// # Errors
    /// Returns [`AdmissionError::IssuerCapReached`] if this issuer has
    /// already vouched for `max_invitees_per_issuer` other distinct
    /// subjects, or any error from [`Invitation::verify`].
    pub fn ingest(&mut self, invite: Invitation, now: u64) -> Result<(), AdmissionError> {
        invite.verify(now)?;
        let issuer = invite.issuer().as_bytes();
        let subject = invite.subject();
        let subjects = self.edges.entry(issuer).or_default();
        if !subjects.contains_key(&subject) && subjects.len() >= self.max_invitees_per_issuer {
            return Err(AdmissionError::IssuerCapReached);
        }
        subjects.insert(subject, invite);
        Ok(())
    }

    /// Is `subject` reachable from a trusted root within `max_depth`
    /// invitation hops, using only invitations that are still valid at `now`?
    #[must_use]
    pub fn is_admitted(&self, subject: &[u8; 32], max_depth: u8, now: u64) -> bool {
        self.trust_depth(subject, max_depth, now).is_some()
    }

    /// Shortest invitation-chain length from a trusted root to `subject`, if
    /// one exists within `max_depth` hops using invitations valid at `now`.
    #[must_use]
    pub fn trust_depth(&self, subject: &[u8; 32], max_depth: u8, now: u64) -> Option<u8> {
        if self.roots.contains(subject) {
            return Some(0);
        }
        let mut frontier: Vec<[u8; 32]> = self.roots.iter().copied().collect();
        let mut visited: HashSet<[u8; 32]> = frontier.iter().copied().collect();
        for depth in 1..=max_depth {
            let mut next = Vec::new();
            for issuer in &frontier {
                let Some(subjects) = self.edges.get(issuer) else {
                    continue;
                };
                for invite in subjects.values() {
                    // Signature was already checked once by `ingest`;
                    // invitations are immutable afterward, so only the
                    // (cheap) time window needs rechecking per query.
                    if !invite.time_valid(now) {
                        continue;
                    }
                    let s = invite.subject();
                    if s == *subject {
                        return Some(depth);
                    }
                    if visited.insert(s) {
                        next.push(s);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> PublicIdentity {
        crate::crypto::keys::IdentitySecret::from_bytes([seed; 32]).public()
    }

    #[test]
    fn issue_and_verify_within_window() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let subject = identity(2);
        let invite = root.issue(&subject, 1_000, 100);
        assert_eq!(invite.verify(999), Err(AdmissionError::NotYetValid));
        assert_eq!(invite.verify(1_000), Ok(()));
        assert_eq!(invite.verify(1_050), Ok(()));
        assert_eq!(invite.verify(1_100), Err(AdmissionError::Expired));
    }

    #[test]
    fn tampered_subject_rejected() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let subject = identity(2);
        let mut invite = root.issue(&subject, 1_000, 100);
        invite.subject[0] ^= 0xFF;
        assert_eq!(invite.verify(1_000), Err(AdmissionError::BadSignature));
    }

    #[test]
    fn tampered_signature_rejected() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let subject = identity(2);
        let mut invite = root.issue(&subject, 1_000, 100);
        invite.signature[0] ^= 0xFF;
        assert_eq!(invite.verify(1_000), Err(AdmissionError::BadSignature));
    }

    #[test]
    fn wire_roundtrip() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let subject = identity(2);
        let invite = root.issue(&subject, 1_000, 100);
        let encoded = invite.encode();
        assert_eq!(encoded.len(), INVITATION_LEN);
        let decoded = Invitation::decode(&encoded).unwrap();
        assert_eq!(decoded.verify(1_050), Ok(()));
        assert_eq!(decoded.subject(), subject.as_bytes());
        assert_eq!(decoded.issuer(), root.public());
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(
            Invitation::decode(&[0u8; 10]).unwrap_err(),
            AdmissionError::BadEncoding
        );
    }

    #[test]
    fn direct_root_is_admitted_at_depth_zero() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let mut store = TrustStore::new();
        store.add_root(root.public());
        let root_as_subject = root.public().as_bytes();
        assert_eq!(store.trust_depth(&root_as_subject, 5, 1_000), Some(0));
    }

    #[test]
    fn chain_admitted_within_depth_not_beyond() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let alice = InviteSigningKey::from_bytes([2; 32]);
        let bob_identity = identity(3);

        let mut store = TrustStore::new();
        store.add_root(root.public());

        // Root vouches for Alice's admission identity (bind her signing key's
        // own bytes as the "subject" of this hop in the chain).
        let alice_as_subject = PublicIdentity::from_bytes(alice.public().as_bytes());
        let root_to_alice = root.issue(&alice_as_subject, 1_000, 1_000);
        store.ingest(root_to_alice, 1_000).unwrap();

        // Alice vouches for Bob's PPoSE identity.
        let alice_to_bob = alice.issue(&bob_identity, 1_000, 1_000);
        store.ingest(alice_to_bob, 1_000).unwrap();

        let bob_bytes = bob_identity.as_bytes();
        assert_eq!(store.trust_depth(&bob_bytes, 1, 1_000), None);
        assert_eq!(store.trust_depth(&bob_bytes, 2, 1_000), Some(2));
        assert!(store.is_admitted(&bob_bytes, 2, 1_000));
    }

    #[test]
    fn expired_edge_stops_admitting_new_queries() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let subject = identity(2);
        let mut store = TrustStore::new();
        store.add_root(root.public());
        let invite = root.issue(&subject, 1_000, 50);
        store.ingest(invite, 1_000).unwrap();

        let subject_bytes = subject.as_bytes();
        assert!(store.is_admitted(&subject_bytes, 1, 1_020));
        assert!(!store.is_admitted(&subject_bytes, 1, 1_060));
    }

    #[test]
    fn issuer_cap_limits_distinct_subjects() {
        let root = InviteSigningKey::from_bytes([1; 32]);
        let mut store = TrustStore::new();
        store.add_root(root.public());
        store.set_max_invitees_per_issuer(1);

        let first = identity(2);
        let second = identity(3);

        store.ingest(root.issue(&first, 1_000, 100), 1_000).unwrap();
        let err = store.ingest(root.issue(&second, 1_000, 100), 1_000);
        assert_eq!(err, Err(AdmissionError::IssuerCapReached));

        // Re-ingesting (e.g. a renewed invitation) for the same subject
        // already under the cap stays allowed.
        store.ingest(root.issue(&first, 1_000, 200), 1_000).unwrap();
    }
}
