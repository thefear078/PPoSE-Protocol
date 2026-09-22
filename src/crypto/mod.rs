//! Cryptographic primitives: keys, Noise XX, optional standalone AEAD helpers.

pub mod aead;
pub mod keys;
pub mod noise;

pub use aead::{AeadError, SessionAead};
pub use keys::{IdentitySecret, PublicIdentity};
pub use noise::{HandshakeRole, NoiseError, NoiseSession};
