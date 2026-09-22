//! Endpoint reliability (Layer 6): selective-repeat ARQ and fragmentation.
//!
//! Relays do **not** run this. Retransmit, ACK, and reassembly are endpoint state.

mod arq;
mod frame;

pub use arq::{Arq, ArqError, ArqGiveUp, WINDOW_SIZE};
pub use frame::{
    decode_inner, encode_ack, encode_data, InnerFrame, ACK_LEN, DATA_HDR_LEN, MAX_PAYLOAD,
};
