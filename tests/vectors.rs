//! Byte-level vectors for the outer header and inner frames.

use ppose::network::packet::{decode_outer, encode_outer, PacketType};
use ppose::reliability::{decode_inner, encode_ack, encode_data, InnerFrame};
use ppose::{MAGIC, PROTOCOL_VERSION};

#[test]
fn outer_header_vector() {
    let hdr = encode_outer(PacketType::Data, 0);
    assert_eq!(hdr[0], MAGIC[0]);
    assert_eq!(hdr[1], MAGIC[1]);
    assert_eq!(hdr[2], PROTOCOL_VERSION);
    assert_eq!(hdr[3], 2);
    assert_eq!(&hdr[4..], &[0, 0, 0, 0]);
    let (ty, flags, body) = decode_outer(&hdr).unwrap();
    assert_eq!(ty, PacketType::Data);
    assert_eq!(flags, 0);
    assert!(body.is_empty());
}

#[test]
fn inner_data_vector() {
    let bytes = encode_data(0x0102_0304, 0x1122, 1, 3, b"xy");
    assert_eq!(bytes[0], 0x01);
    assert_eq!(&bytes[1..5], &[1, 2, 3, 4]);
    match decode_inner(&bytes).unwrap() {
        InnerFrame::Data {
            seq,
            frag_id,
            index,
            total,
            payload,
        } => {
            assert_eq!(seq, 0x0102_0304);
            assert_eq!(frag_id, 0x1122);
            assert_eq!(index, 1);
            assert_eq!(total, 3);
            assert_eq!(payload, b"xy");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn inner_ack_vector() {
    let bytes = encode_ack(9, 0x8000_0000_0000_0001);
    match decode_inner(&bytes).unwrap() {
        InnerFrame::Ack { base, bitmap } => {
            assert_eq!(base, 9);
            assert_eq!(bitmap, 0x8000_0000_0000_0001);
        }
        other => panic!("{other:?}"),
    }
}
