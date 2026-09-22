//! Noise XX handshake and transport via `snow`.

use snow::params::NoiseParams;
use snow::Builder;
use thiserror::Error;

use crate::crypto::keys::IdentitySecret;
use crate::NOISE_PARAMS;

/// Handshake role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// Sends the first Noise message.
    Initiator,
    /// Responds to the first Noise message.
    Responder,
}

/// Noise-layer errors.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// Parameter / builder failure.
    #[error("noise setup: {0}")]
    Setup(String),
    /// Handshake or transport crypto failure.
    #[error("noise crypto: {0}")]
    Crypto(String),
    /// Operation not valid in the current state.
    #[error("invalid session state")]
    BadState,
}

/// Noise XX session (handshake then transport).
pub struct NoiseSession {
    handshake: Option<snow::HandshakeState>,
    transport: Option<snow::TransportState>,
}

impl NoiseSession {
    /// Start a new Noise XX session with a local static key.
    pub fn new(role: HandshakeRole, local: &IdentitySecret) -> Result<Self, NoiseError> {
        let params: NoiseParams = NOISE_PARAMS
            .parse()
            .map_err(|e| NoiseError::Setup(format!("{e}")))?;
        let static_key = local.to_bytes();
        let builder = Builder::new(params).local_private_key(&static_key);
        let hs = match role {
            HandshakeRole::Initiator => builder
                .build_initiator()
                .map_err(|e| NoiseError::Setup(format!("{e}")))?,
            HandshakeRole::Responder => builder
                .build_responder()
                .map_err(|e| NoiseError::Setup(format!("{e}")))?,
        };
        Ok(Self {
            handshake: Some(hs),
            transport: None,
        })
    }

    /// Whether transport mode is active.
    pub fn is_transport(&self) -> bool {
        self.transport.is_some()
    }

    /// Write the next handshake message.
    pub fn write_handshake(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let hs = self.handshake.as_mut().ok_or(NoiseError::BadState)?;
        let n = hs
            .write_message(payload, out)
            .map_err(|e| NoiseError::Crypto(format!("{e}")))?;
        self.maybe_finish()?;
        Ok(n)
    }

    /// Read the next handshake message.
    pub fn read_handshake(&mut self, msg: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let hs = self.handshake.as_mut().ok_or(NoiseError::BadState)?;
        let n = hs
            .read_message(msg, out)
            .map_err(|e| NoiseError::Crypto(format!("{e}")))?;
        self.maybe_finish()?;
        Ok(n)
    }

    fn maybe_finish(&mut self) -> Result<(), NoiseError> {
        let finished = self
            .handshake
            .as_ref()
            .map(snow::HandshakeState::is_handshake_finished)
            .unwrap_or(false);
        if finished {
            let hs = self.handshake.take().ok_or(NoiseError::BadState)?;
            let ts = hs
                .into_transport_mode()
                .map_err(|e| NoiseError::Crypto(format!("{e}")))?;
            self.transport = Some(ts);
        }
        Ok(())
    }

    /// Encrypt an application payload in transport mode.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let ts = self.transport.as_mut().ok_or(NoiseError::BadState)?;
        ts.write_message(plaintext, out)
            .map_err(|e| NoiseError::Crypto(format!("{e}")))
    }

    /// Decrypt an application payload in transport mode.
    pub fn open(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, NoiseError> {
        let ts = self.transport.as_mut().ok_or(NoiseError::BadState)?;
        ts.read_message(ciphertext, out)
            .map_err(|e| NoiseError::Crypto(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::IdentitySecret;

    #[test]
    fn noise_xx_handshake_and_transport() {
        let alice_id = IdentitySecret::generate();
        let bob_id = IdentitySecret::generate();
        let mut alice = NoiseSession::new(HandshakeRole::Initiator, &alice_id).unwrap();
        let mut bob = NoiseSession::new(HandshakeRole::Responder, &bob_id).unwrap();

        let mut buf_a = [0u8; 1024];
        let mut buf_b = [0u8; 1024];
        let mut tmp = [0u8; 1024];

        // → msg 1
        let n = alice.write_handshake(&[], &mut buf_a).unwrap();
        bob.read_handshake(&buf_a[..n], &mut tmp).unwrap();

        // ← msg 2
        let n = bob.write_handshake(&[], &mut buf_b).unwrap();
        alice.read_handshake(&buf_b[..n], &mut tmp).unwrap();

        // → msg 3
        let n = alice.write_handshake(&[], &mut buf_a).unwrap();
        bob.read_handshake(&buf_a[..n], &mut tmp).unwrap();

        assert!(alice.is_transport());
        assert!(bob.is_transport());

        let msg = b"ppose-phase1";
        let n = alice.seal(msg, &mut buf_a).unwrap();
        let m = bob.open(&buf_a[..n], &mut buf_b).unwrap();
        assert_eq!(&buf_b[..m], msg);
    }
}
