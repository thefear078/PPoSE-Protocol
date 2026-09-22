//! Framing and UDP helpers.

pub mod packet;
pub mod udp;

pub use packet::{decode_outer, encode_outer, PacketType};
