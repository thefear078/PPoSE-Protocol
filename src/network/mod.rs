//! Networking layer (L1–L4): transport, NAT, rendezvous, packets, routing.

pub mod packet;

pub use packet::{PacketType, HEADER_LEN};
