//! Client network layer: the dual HTTP streams and the downlink router.
//!
//! Owner: W12 (E5). See 41 §2.8, 44 §2, 51 §3.2 and 53 W12.
//!
//! ```text
//! POST {prefix}/rpc     uplink   (client -> server frames)
//! GET  {prefix}/events  downlink (server -> client frames)
//! ```
//!
//! The two requests are independent TCP connections and are paired only by
//! the `X-SM-Nonce` header (W8). [`conn::Conn`] owns both until the HELLO /
//! WELCOME handshake succeeds, then splits into [`conn::Uplink`] and
//! [`downlink::Downlink`]. The split is deliberate: only the downlink task
//! reads the events stream, and only the uplink task writes the RPC stream.
//!
//! The downlink never interprets ciphertext. It validates frame boundaries
//! and flags, routes plaintext control frames (WELCOME/PONG/KICK/ERROR/FLOW/
//! SYNC_END/LEAVE), and forwards sealed frames as owned [`FrameBuf`] values on
//! a bounded channel. [`downlink::decode_ordered`] is the explicit seam where
//! the replay pump authenticates and decodes an `ORDERED` body.
//!
//! [`heartbeat`] decides when the uplink must report a changed applied
//! watermark in a `PING`; an unchanged watermark sends nothing.
//! [`uplink::UplinkTask`] remains the only writer of the RPC stream, so the
//! heartbeat never opens a second one.

pub mod conn;
pub mod data;
pub mod downlink;
pub mod heartbeat;
pub mod holder;
pub mod join_proof;
pub mod scoped;
pub mod uplink;

use crate::protocol::{
    BodyEncoding, Flags, FrameEncoder, FrameHeader, FrameRef, MsgType, Prefix, PrefixKind,
    ProtocolError, Seq,
};

pub use crate::transport::DialOptions as ConnOptions;
pub use conn::{Conn, ConnError, ConnParts, Uplink, UplinkError};
pub use data::{DataCache, DataError};
pub use downlink::{
    Downlink, DownlinkError, DownlinkHandle, DownlinkItem, DownlinkOutcome, decode_ordered,
};
pub use heartbeat::{Heartbeat, MIN_REPORT_INTERVAL, Watermark, WatermarkReader, ping_frame};
pub use holder::{Holder, HolderError, HolderView};
pub use join_proof::JoinProofResponder;
pub use scoped::{FrameWriter, ScopedError, ScopedHandle, ScopedUplink};
pub use uplink::UplinkTask;

/// Wall clock in microseconds for the status trace.
pub(crate) fn wall_clock_us() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Default bound on the ORDERED/RESPONSE/RELAY channel (41 §7.1).
pub const DEFAULT_DOWNLINK_DEPTH: usize = 1_024;

/// Encode one client-authored control frame.
///
/// The length field is derived from the parts; the caller only chooses the
/// message type, prefix and sequence. This mirrors the server's
/// `encode_control` and keeps `len` unrepresentable as a caller mistake
/// (44 INV-01).
pub(crate) fn encode_control(
    msg_type: MsgType,
    prefix: Prefix,
    body: &[u8],
    seq: Seq,
) -> Result<Vec<u8>, ProtocolError> {
    let mut flags = Flags::EMPTY;
    match prefix.kind() {
        PrefixKind::None => {}
        PrefixKind::Route => flags = flags.with(Flags::ROUTED),
        PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
    }
    if msg_type.body_encoding() == BodyEncoding::Sealed {
        flags = flags.with(Flags::ENC);
    }
    let mut header = FrameHeader::new(msg_type, flags, 0, seq);
    let len = prefix
        .encoded_len()
        .checked_add(body.len())
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(ProtocolError::BadLen {
            len: u32::MAX,
            prefix: prefix.encoded_len() as u8,
            cap: crate::protocol::FRAME_MAX,
        })?;
    header.len = len;
    let mut encoder = FrameEncoder::with_capacity(
        crate::protocol::HEADER_LEN + prefix.encoded_len() + body.len(),
    );
    encoder.encode_owned(&FrameRef::new(&header, &prefix, body))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::{FrameDecoder, Limits};

    /// 44 INV-01: the encoder, not the caller, owns `len`.
    #[test]
    fn u_net_control_frame_roundtrip() {
        let body = [1_u8, 2, 3, 4];
        let bytes = encode_control(MsgType::KICK, Prefix::None, &body, Seq::UNSEQUENCED)
            .unwrap_or_else(|err| panic!("encode: {err}"));
        let mut decoder = FrameDecoder::new(Limits::default());
        decoder
            .push(&bytes)
            .unwrap_or_else(|err| panic!("push: {err}"));
        let frame = decoder
            .next_frame_owned()
            .unwrap_or_else(|err| panic!("decode: {err}"))
            .unwrap_or_else(|| panic!("frame missing"));
        assert_eq!(frame.header.msg_type, MsgType::KICK);
        assert_eq!(frame.header.len, body.len() as u32);
        assert_eq!(frame.body, body);
        assert_eq!(frame.header.seq, Seq::UNSEQUENCED);
        assert!(decoder.is_empty());
    }
}
