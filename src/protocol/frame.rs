//! Frame header, prefixes, identifiers and length limits.
//!
//! This file is the single source of truth for wire widths. The three
//! constants below are asserted at compile time so that the 17 B / 22 B
//! arithmetic slips recorded in 48 can never come back:
//!
//! ```text
//! header        = magic u8 | ver u8 | type u8 | flags u16
//!               | req_id u32 | len u32 | seq u64          = 21
//! route_prefix  = session_id u128 | stream u8
//!               | chunk_index u32 | total_chunks u32      = 25
//! ctrl_prefix   = applied_seq u64 | epoch_seen u64
//!               | reserved u16                            = 18
//! ```

use std::fmt;

use crate::protocol::errors::ProtocolError;
use crate::protocol::version::FrameVer;
use crate::protocol::{ENV_OVERHEAD, FRAME_MAX, INGRESS_FRAME, MAX_CHUNKS};

/// First header byte. `0x53` is ASCII `S`.
pub const MAGIC: u8 = 0x53;

/// Fixed header width in bytes.
pub const HEADER_LEN: usize = 21;

/// Width of the plaintext route prefix in bytes.
pub const ROUTE_PREFIX_LEN: usize = 25;

/// Width of the plaintext control prefix in bytes.
pub const CTRL_PREFIX_LEN: usize = 18;

/// Smallest legal plaintext body: one minimal WCP field.
pub const MIN_PLAIN_BODY: u32 = 3;

// Compile-time arithmetic: a wrong constant fails the build, not a test run.
const _: () = {
    assert!(HEADER_LEN == 1 + 1 + 1 + 2 + 4 + 4 + 8);
    assert!(HEADER_LEN == 21);
    assert!(ROUTE_PREFIX_LEN == 16 + 1 + 4 + 4);
    assert!(ROUTE_PREFIX_LEN == 25);
    assert!(CTRL_PREFIX_LEN == 8 + 8 + 2);
    assert!(CTRL_PREFIX_LEN == 18);
    assert!(HEADER_LEN + ROUTE_PREFIX_LEN + ENV_OVERHEAD as usize <= INGRESS_FRAME as usize);
};

/// Prefix family implied by `flags.bit4`/`flags.bit5`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum PrefixKind {
    /// No prefix.
    #[default]
    None,
    /// 25-byte route prefix.
    Route,
    /// 18-byte control prefix.
    Ctrl,
}

impl PrefixKind {
    /// Encoded width in bytes.
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Route => ROUTE_PREFIX_LEN,
            Self::Ctrl => CTRL_PREFIX_LEN,
        }
    }

    /// AAD tag value: 0 = none, 1 = route, 2 = ctrl (44 §4.3).
    pub const fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Route => 1,
            Self::Ctrl => 2,
        }
    }
}

/// How a frame body is encoded.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BodyEncoding {
    /// Plain WCP bytes.
    Plain,
    /// AEAD envelope `[alg][kid][nonce 12][ct][tag 16]`.
    Sealed,
}

impl BodyEncoding {
    /// Whether this encoding is AEAD-sealed.
    pub const fn is_sealed(self) -> bool {
        matches!(self, Self::Sealed)
    }

    /// Smallest legal body for this encoding.
    pub const fn min_body_len(self) -> u32 {
        match self {
            Self::Plain => MIN_PLAIN_BODY,
            Self::Sealed => ENV_OVERHEAD,
        }
    }
}

/// Frame header flags (`u16`, little endian).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flags(u16);

impl Flags {
    /// Sender asks for priority handling.
    pub const URGENT: Self = Self(1 << 0);
    /// Body is compressed. Off in v1.
    pub const COMPRESSED: Self = Self(1 << 1);
    /// End of a fragmented logical message.
    pub const FIN: Self = Self(1 << 2);
    /// Body is an AEAD envelope. Must match the type table.
    pub const ENC: Self = Self(1 << 3);
    /// A 25-byte route prefix precedes the body.
    pub const ROUTED: Self = Self(1 << 4);
    /// An 18-byte control prefix precedes the body.
    pub const CTRL: Self = Self(1 << 5);

    /// Bits 6 and 7 are reserved and must be zero (44 INV-02).
    ///
    /// These are bit positions inside the `u16`, not byte positions:
    /// `0x0040 | 0x0080`.
    pub const RESERVED_MASK: u16 = 0x00c0;

    /// No flags.
    pub const EMPTY: Self = Self(0);

    /// Raw bits.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Wrap raw bits without validation.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set union.
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove every bit of `other`.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether any reserved bit is set.
    pub const fn has_reserved_bits(self) -> bool {
        (self.0 & Self::RESERVED_MASK) != 0
    }

    /// Prefix family implied by bits 4 and 5.
    ///
    /// Both bits set at once is a conflict, not a third kind.
    pub fn prefix_kind(self) -> Result<PrefixKind, ProtocolError> {
        match (self.contains(Self::ROUTED), self.contains(Self::CTRL)) {
            (false, false) => Ok(PrefixKind::None),
            (true, false) => Ok(PrefixKind::Route),
            (false, true) => Ok(PrefixKind::Ctrl),
            (true, true) => Err(ProtocolError::FlagsConflict(self.0)),
        }
    }

    /// Check this flag set against the message type it claims to describe.
    pub fn validate(self, msg_type: MsgType) -> Result<(), ProtocolError> {
        if self.has_reserved_bits() {
            return Err(ProtocolError::ReservedFlags(self.0));
        }
        if self.prefix_kind()? != msg_type.prefix_kind() {
            return Err(ProtocolError::UnexpectedPrefix);
        }
        if self.contains(Self::ENC) != msg_type.body_encoding().is_sealed() {
            return Err(ProtocolError::FlagsConflict(self.0));
        }
        Ok(())
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Flags(0x{:04x})", self.0)
    }
}

/// One of the 16 defined message types (44 §3.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsgType(u8);

impl MsgType {
    /// Client hello; plain WCP with a control prefix.
    pub const HELLO: Self = Self(0x01);
    /// Server welcome; plain WCP.
    pub const WELCOME: Self = Self(0x02);
    /// Client handshake authentication; sealed under the handshake key.
    pub const AUTH: Self = Self(0x03);
    /// Server handshake acceptance; sealed under the handshake key.
    pub const ACCEPT: Self = Self(0x04);
    /// Sequenced operation; sealed WCP.
    pub const ORDERED: Self = Self(0x10);
    /// Operation response; sealed WCP.
    pub const RESPONSE: Self = Self(0x11);
    /// Routed relay message; sealed WCP.
    pub const RELAY: Self = Self(0x12);
    /// Acknowledged operations; sealed WCP.
    pub const ACK: Self = Self(0x13);
    /// Client heartbeat; sealed WCP with a control prefix.
    pub const PING: Self = Self(0x14);
    /// Server heartbeat reply; sealed WCP.
    pub const PONG: Self = Self(0x15);
    /// Transport-level error; plain WCP.
    pub const ERROR: Self = Self(0x16);
    /// Server kick; sealed WCP.
    pub const KICK: Self = Self(0x17);
    /// Flow-control grant; sealed WCP with a route prefix.
    pub const FLOW: Self = Self(0x18);
    /// End of a sync session; sealed WCP with a route prefix.
    pub const SYNC_END: Self = Self(0x19);
    /// Raw sealed stream chunk with a route prefix.
    pub const STREAM_DATA: Self = Self(0x1A);
    /// Server-injected leave notice; sealed WCP.
    pub const LEAVE: Self = Self(0x1B);

    /// Every defined type, in wire order. Used by table-driven tests.
    pub const ALL: [Self; 16] = [
        Self::HELLO,
        Self::WELCOME,
        Self::AUTH,
        Self::ACCEPT,
        Self::ORDERED,
        Self::RESPONSE,
        Self::RELAY,
        Self::ACK,
        Self::PING,
        Self::PONG,
        Self::ERROR,
        Self::KICK,
        Self::FLOW,
        Self::SYNC_END,
        Self::STREAM_DATA,
        Self::LEAVE,
    ];

    /// Raw byte.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Decode a type byte, rejecting anything outside the table.
    pub fn from_u8(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            0x01 => Ok(Self::HELLO),
            0x02 => Ok(Self::WELCOME),
            0x03 => Ok(Self::AUTH),
            0x04 => Ok(Self::ACCEPT),
            0x10 => Ok(Self::ORDERED),
            0x11 => Ok(Self::RESPONSE),
            0x12 => Ok(Self::RELAY),
            0x13 => Ok(Self::ACK),
            0x14 => Ok(Self::PING),
            0x15 => Ok(Self::PONG),
            0x16 => Ok(Self::ERROR),
            0x17 => Ok(Self::KICK),
            0x18 => Ok(Self::FLOW),
            0x19 => Ok(Self::SYNC_END),
            0x1A => Ok(Self::STREAM_DATA),
            0x1B => Ok(Self::LEAVE),
            other => Err(ProtocolError::UnknownType(other)),
        }
    }

    /// Whether a raw byte is a defined type.
    pub const fn is_known_raw(raw: u8) -> bool {
        matches!(
            raw,
            0x01 | 0x02
                | 0x03
                | 0x04
                | 0x10
                | 0x11
                | 0x12
                | 0x13
                | 0x14
                | 0x15
                | 0x16
                | 0x17
                | 0x18
                | 0x19
                | 0x1A
                | 0x1B
        )
    }

    /// Prefix family this type requires.
    pub const fn prefix_kind(self) -> PrefixKind {
        match self.0 {
            0x01 | 0x14 => PrefixKind::Ctrl,
            0x12 | 0x18 | 0x19 | 0x1A => PrefixKind::Route,
            _ => PrefixKind::None,
        }
    }

    /// Body encoding this type requires.
    ///
    /// Plain frames are exactly the ones a peer must read before it holds a
    /// key: `HELLO`, `WELCOME` and `ERROR`. Everything else is sealed.
    pub const fn body_encoding(self) -> BodyEncoding {
        match self.0 {
            0x01 | 0x02 | 0x16 => BodyEncoding::Plain,
            _ => BodyEncoding::Sealed,
        }
    }

    /// Stable name for logs and golden vectors.
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x01 => "HELLO",
            0x02 => "WELCOME",
            0x03 => "AUTH",
            0x04 => "ACCEPT",
            0x10 => "ORDERED",
            0x11 => "RESPONSE",
            0x12 => "RELAY",
            0x13 => "ACK",
            0x14 => "PING",
            0x15 => "PONG",
            0x16 => "ERROR",
            0x17 => "KICK",
            0x18 => "FLOW",
            0x19 => "SYNC_END",
            0x1A => "STREAM_DATA",
            0x1B => "LEAVE",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Debug for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MsgType({}:{})", self.name(), self.0)
    }
}

/// A sync session identifier. 128 random bits, unguessable by design.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SessionId(pub u128);

impl SessionId {
    /// Encoded width.
    pub const LEN: usize = 16;

    /// The all-zero identifier, used as "no session".
    pub const ZERO: Self = Self(0);

    /// Wrap a raw value.
    pub const fn new(raw: u128) -> Self {
        Self(raw)
    }

    /// Raw value.
    pub const fn get(self) -> u128 {
        self.0
    }

    /// Little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; Self::LEN] {
        self.0.to_le_bytes()
    }

    /// Decode little-endian wire bytes.
    pub const fn from_le_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({:032x})", self.0)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// A stream number inside a sync session.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct StreamId(pub u8);

impl StreamId {
    /// Block stream.
    pub const BLOCK: Self = Self(2);
    /// Operation data stream.
    pub const OP_DATA: Self = Self(3);
    /// Control stream.
    pub const CTRL: Self = Self(4);

    /// Raw value.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A server-assigned global sequence number.
///
/// Zero means "not sequenced": every uplink frame and every unordered
/// downlink frame carries it. Real sequence numbers start at one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Seq(pub u64);

impl Seq {
    /// The "not sequenced" sentinel.
    pub const UNSEQUENCED: Self = Self(0);
    /// The first sequence number a server assigns.
    pub const FIRST: Self = Self(1);

    /// Raw value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether a real sequence number was assigned.
    pub const fn is_sequenced(self) -> bool {
        self.0 != 0
    }

    /// Next sequence number, or `None` at the u64 ceiling.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A client identity: 16 bytes derived from the client key (50 D2).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId([u8; 16]);

impl ClientId {
    /// Encoded width.
    pub const LEN: usize = 16;

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Copy the raw bytes.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}

impl fmt::Debug for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientId({self})")
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// An operation identifier: 16 bytes, unique per `(instance, local_seq)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId([u8; 16]);

impl OpId {
    /// Encoded width.
    pub const LEN: usize = 16;

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Copy the raw bytes.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        self.0
    }
}

impl fmt::Debug for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OpId({self})")
    }
}

impl fmt::Display for OpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Plaintext route prefix for `RELAY`/`STREAM_DATA`/`FLOW`/`SYNC_END`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RoutePrefix {
    /// Session this frame belongs to.
    pub session_id: SessionId,
    /// Stream number inside the session.
    pub stream: StreamId,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total chunks; zero for control frames that are not fragmented.
    pub total_chunks: u32,
}

impl RoutePrefix {
    /// Encoded width.
    pub const ENCODED_LEN: usize = ROUTE_PREFIX_LEN;

    /// Build a prefix.
    pub const fn new(
        session_id: SessionId,
        stream: StreamId,
        chunk_index: u32,
        total_chunks: u32,
    ) -> Self {
        Self {
            session_id,
            stream,
            chunk_index,
            total_chunks,
        }
    }

    /// Little-endian wire bytes.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..SessionId::LEN].copy_from_slice(&self.session_id.to_le_bytes());
        out[SessionId::LEN] = self.stream.get();
        out[17..21].copy_from_slice(&self.chunk_index.to_le_bytes());
        out[21..25].copy_from_slice(&self.total_chunks.to_le_bytes());
        out
    }

    /// Decode exactly [`RoutePrefix::ENCODED_LEN`] bytes.
    pub fn decode(src: &[u8]) -> Result<Self, ProtocolError> {
        if src.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::Truncated {
                need: Self::ENCODED_LEN,
                got: src.len(),
            });
        }
        let mut sid = [0u8; SessionId::LEN];
        sid.copy_from_slice(&src[..SessionId::LEN]);
        Ok(Self {
            session_id: SessionId::from_le_bytes(sid),
            stream: StreamId(src[SessionId::LEN]),
            chunk_index: u32::from_le_bytes([src[17], src[18], src[19], src[20]]),
            total_chunks: u32::from_le_bytes([src[21], src[22], src[23], src[24]]),
        })
    }

    /// Check chunk bookkeeping.
    ///
    /// Enforced by the fragment layer (`Fragmenter`/`Reassembler`), not by the
    /// frame decoder: a control frame legitimately carries zero for both
    /// fields, and routing does not need the values.
    pub fn check_chunk_bounds(&self) -> Result<(), ProtocolError> {
        if self.total_chunks == 0 {
            if self.chunk_index != 0 {
                return Err(ProtocolError::BadChunkBounds {
                    chunk_index: self.chunk_index,
                    total_chunks: 0,
                });
            }
            return Ok(());
        }
        if self.chunk_index >= self.total_chunks || self.total_chunks > MAX_CHUNKS {
            return Err(ProtocolError::BadChunkBounds {
                chunk_index: self.chunk_index,
                total_chunks: self.total_chunks,
            });
        }
        Ok(())
    }
}

/// Plaintext control prefix for `HELLO`/`PING`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct CtrlPrefix {
    /// Highest sequence number the client has applied.
    pub applied_seq: Seq,
    /// Server epoch the client last saw.
    pub epoch_seen: u64,
    /// Reserved; must be zero.
    pub reserved: u16,
}

impl CtrlPrefix {
    /// Encoded width.
    pub const ENCODED_LEN: usize = CTRL_PREFIX_LEN;

    /// Build a prefix with the reserved field zeroed.
    pub const fn new(applied_seq: Seq, epoch_seen: u64) -> Self {
        Self {
            applied_seq,
            epoch_seen,
            reserved: 0,
        }
    }

    /// Little-endian wire bytes.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..8].copy_from_slice(&self.applied_seq.get().to_le_bytes());
        out[8..16].copy_from_slice(&self.epoch_seen.to_le_bytes());
        out[16..18].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    /// Decode exactly [`CtrlPrefix::ENCODED_LEN`] bytes.
    ///
    /// This is a pure field decoder: it preserves `reserved` as received.
    /// [`Prefix::decode`] is the frame-level entry and rejects a non-zero
    /// value there (44 §2.1: `reserved u16 (=0)`).
    pub fn decode(src: &[u8]) -> Result<Self, ProtocolError> {
        if src.len() != Self::ENCODED_LEN {
            return Err(ProtocolError::Truncated {
                need: Self::ENCODED_LEN,
                got: src.len(),
            });
        }
        Ok(Self {
            applied_seq: Seq(u64::from_le_bytes([
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            ])),
            epoch_seen: u64::from_le_bytes([
                src[8], src[9], src[10], src[11], src[12], src[13], src[14], src[15],
            ]),
            reserved: u16::from_le_bytes([src[16], src[17]]),
        })
    }

    /// Check the reserved field.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.reserved != 0 {
            return Err(ProtocolError::NonZeroReserved(self.reserved));
        }
        Ok(())
    }
}

/// The prefix carried by a frame.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Prefix {
    /// No prefix.
    #[default]
    None,
    /// Route prefix.
    Route(RoutePrefix),
    /// Control prefix.
    Ctrl(CtrlPrefix),
}

impl Prefix {
    /// Prefix family.
    pub const fn kind(&self) -> PrefixKind {
        match self {
            Self::None => PrefixKind::None,
            Self::Route(_) => PrefixKind::Route,
            Self::Ctrl(_) => PrefixKind::Ctrl,
        }
    }

    /// Encoded width in bytes.
    pub const fn encoded_len(&self) -> usize {
        self.kind().encoded_len()
    }

    /// Append the encoded prefix to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::None => {}
            Self::Route(route) => out.extend_from_slice(&route.encode()),
            Self::Ctrl(ctrl) => out.extend_from_slice(&ctrl.encode()),
        }
    }

    /// Decode a prefix of the given family.
    ///
    /// A control prefix with a non-zero `reserved` field is rejected here:
    /// the frame decoder never lets it reach a caller.
    pub fn decode(kind: PrefixKind, src: &[u8]) -> Result<Self, ProtocolError> {
        match kind {
            PrefixKind::None => {
                if src.is_empty() {
                    Ok(Self::None)
                } else {
                    Err(ProtocolError::UnexpectedPrefix)
                }
            }
            PrefixKind::Route => Ok(Self::Route(RoutePrefix::decode(src)?)),
            PrefixKind::Ctrl => {
                let ctrl = CtrlPrefix::decode(src)?;
                ctrl.validate()?;
                Ok(Self::Ctrl(ctrl))
            }
        }
    }

    /// Borrow the route prefix, if any.
    pub const fn as_route(&self) -> Option<&RoutePrefix> {
        match self {
            Self::Route(route) => Some(route),
            _ => None,
        }
    }

    /// Borrow the control prefix, if any.
    pub const fn as_ctrl(&self) -> Option<&CtrlPrefix> {
        match self {
            Self::Ctrl(ctrl) => Some(ctrl),
            _ => None,
        }
    }
}

/// Parser limits. Only bounds parsing; no policy lives here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Limits {
    /// Largest accepted `len` field.
    pub ingress_frame: u32,
    /// Largest accepted WCP body.
    pub wcp_max: u16,
    /// Largest accepted path.
    pub path_max: u16,
    /// Largest accepted error detail.
    pub detail_max: u16,
}

impl Limits {
    /// Limits suitable for a server or client ingress path.
    pub const fn default_const() -> Self {
        Self {
            ingress_frame: INGRESS_FRAME,
            wcp_max: 65535,
            path_max: 4096,
            detail_max: 512,
        }
    }

    /// Limits at the protocol ceiling. Only for conformance vectors.
    pub const fn protocol() -> Self {
        Self {
            ingress_frame: FRAME_MAX,
            wcp_max: 65535,
            path_max: 4096,
            detail_max: 512,
        }
    }

    /// Effective cap: never above the protocol ceiling.
    pub const fn effective_cap(&self) -> u32 {
        if self.ingress_frame < FRAME_MAX {
            self.ingress_frame
        } else {
            FRAME_MAX
        }
    }

    /// Reject limits that cannot describe any legal frame.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let minimum = (HEADER_LEN + ENV_OVERHEAD as usize) as u32;
        if self.ingress_frame < minimum || self.ingress_frame > FRAME_MAX {
            return Err(ProtocolError::InvalidLimits {
                ingress_frame: self.ingress_frame,
                cap: FRAME_MAX,
            });
        }
        Ok(())
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::default_const()
    }
}

/// The fixed 21-byte frame header.
///
/// `magic` is not stored: it is a constant written by [`FrameHeader::encode`]
/// and checked by [`FrameHeader::decode`]. `len` counts prefix plus body and
/// excludes the header. Only the sealer and the plain-frame builder set it;
/// [`crate::protocol::codec::FrameEncoder`] rejects any inconsistency.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FrameHeader {
    /// Frame format version; see [`FrameVer`].
    pub ver: u8,
    /// Message type.
    pub msg_type: MsgType,
    /// Flag bits.
    pub flags: Flags,
    /// Request correlation identifier; zero for broadcasts.
    pub req_id: u32,
    /// Prefix plus body length.
    pub len: u32,
    /// Server sequence number; zero while unsequenced.
    pub seq: Seq,
}

impl FrameHeader {
    /// Build a header for the current frame version with `len = 0`.
    pub const fn new(msg_type: MsgType, flags: Flags, req_id: u32, seq: Seq) -> Self {
        Self {
            ver: FrameVer::CURRENT.get(),
            msg_type,
            flags,
            req_id,
            len: 0,
            seq,
        }
    }

    /// The magic byte, always [`MAGIC`].
    ///
    /// Stored as a constant rather than a field: a header with any other
    /// magic cannot be constructed, so the illegal state is unrepresentable.
    pub const fn magic(&self) -> u8 {
        MAGIC
    }

    /// Encode the fixed header.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = MAGIC;
        out[1] = self.ver;
        out[2] = self.msg_type.get();
        out[3..5].copy_from_slice(&self.flags.bits().to_le_bytes());
        out[5..9].copy_from_slice(&self.req_id.to_le_bytes());
        out[9..13].copy_from_slice(&self.len.to_le_bytes());
        out[13..21].copy_from_slice(&self.seq.get().to_le_bytes());
        out
    }

    /// Decode and validate the fixed header.
    ///
    /// Checks magic, frame version, type and flag consistency. Length bounds
    /// need [`Limits`] and are checked separately by
    /// [`FrameHeader::validate_len`].
    pub fn decode(src: &[u8]) -> Result<Self, ProtocolError> {
        if src.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated {
                need: HEADER_LEN,
                got: src.len(),
            });
        }
        if src[0] != MAGIC {
            return Err(ProtocolError::BadMagic(src[0]));
        }
        let ver = src[1];
        if !FrameVer::is_supported_raw(ver) {
            return Err(ProtocolError::UnsupportedFrameVer(ver));
        }
        let msg_type = MsgType::from_u8(src[2])?;
        let flags = Flags::from_bits(u16::from_le_bytes([src[3], src[4]]));
        flags.validate(msg_type)?;
        Ok(Self {
            ver,
            msg_type,
            flags,
            req_id: u32::from_le_bytes([src[5], src[6], src[7], src[8]]),
            len: u32::from_le_bytes([src[9], src[10], src[11], src[12]]),
            seq: Seq(u64::from_le_bytes([
                src[13], src[14], src[15], src[16], src[17], src[18], src[19], src[20],
            ])),
        })
    }

    /// Prefix width implied by the flags.
    pub fn prefix_len(&self) -> Result<u32, ProtocolError> {
        Ok(self.flags.prefix_kind()?.encoded_len() as u32)
    }

    /// Body length implied by `len` and the flags.
    pub fn body_len(&self) -> Result<u32, ProtocolError> {
        let prefix = self.prefix_len()?;
        self.len.checked_sub(prefix).ok_or(ProtocolError::BadLen {
            len: self.len,
            prefix: prefix as u8,
            cap: self.len,
        })
    }

    /// Whole-frame width including the header.
    pub fn total_len(&self) -> usize {
        HEADER_LEN + self.len as usize
    }

    /// Check `len` against the prefix width, the minimum body and the cap.
    pub fn validate_len(&self, limits: &Limits) -> Result<(), ProtocolError> {
        let prefix = self.prefix_len()?;
        let min_body = self.msg_type.body_encoding().min_body_len();
        let min_len = prefix + min_body;
        let cap = limits.effective_cap();
        if self.len > cap {
            return Err(ProtocolError::BadLen {
                len: self.len,
                prefix: prefix as u8,
                cap,
            });
        }
        if self.len < min_len {
            return Err(ProtocolError::BodyTooShort {
                len: self.len,
                prefix: prefix as u8,
                min_body,
            });
        }
        Ok(())
    }

    /// Re-broadcast helper: change `seq` and nothing else.
    ///
    /// INV-17: every other header byte, the prefix and the body stay
    /// byte-identical, otherwise the AEAD tag would fail at every receiver.
    pub const fn with_seq(&self, seq: Seq) -> Self {
        Self { seq, ..*self }
    }
}

/// An owned frame. Used across task boundaries and by the test ports.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrameBuf {
    /// Header.
    pub header: FrameHeader,
    /// Prefix.
    pub prefix: Prefix,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl FrameBuf {
    /// Build an owned frame.
    pub fn new(header: FrameHeader, prefix: Prefix, body: Vec<u8>) -> Self {
        Self {
            header,
            prefix,
            body,
        }
    }

    /// Borrow as a zero-copy view.
    pub fn as_frame(&self) -> Frame<'_> {
        Frame {
            header: self.header,
            prefix: self.prefix,
            body: &self.body,
        }
    }

    /// Split into parts.
    pub fn into_parts(self) -> (FrameHeader, Prefix, Vec<u8>) {
        (self.header, self.prefix, self.body)
    }

    /// Encoded width including the header.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.prefix.encoded_len() + self.body.len()
    }
}

/// A borrowed frame view. The body points into the decoder buffer and is
/// invalidated by the next decode call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Frame<'a> {
    /// Header.
    pub header: FrameHeader,
    /// Prefix.
    pub prefix: Prefix,
    /// Body bytes.
    pub body: &'a [u8],
}

impl Frame<'_> {
    /// Copy into an owned frame.
    pub fn to_buf(&self) -> FrameBuf {
        FrameBuf::new(self.header, self.prefix, self.body.to_vec())
    }

    /// Body length.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Encoded width including the header.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.prefix.encoded_len() + self.body.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::protocol::{FRAME_MAX, MAX_CHUNKS};

    /// Golden frame 1: plain `WELCOME`, no prefix, five-byte WCP body.
    const GOLDEN_WELCOME: [u8; 26] = [
        0x53, 0x01, 0x02, 0x00, 0x00, // magic, ver, type, flags
        0x00, 0x00, 0x00, 0x00, // req_id
        0x05, 0x00, 0x00, 0x00, // len
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // seq
        0x01, 0x02, 0x00, 0x01, 0x00, // F_WCP_VER = 1
    ];

    /// Golden frame 2: sealed `RELAY` with a 25-byte route prefix and a
    /// minimal 30-byte envelope.
    const GOLDEN_RELAY: [u8; 76] = [
        0x53, 0x01, 0x12, 0x18, 0x00, // magic, ver, type, flags = ENC|ROUTED
        0x44, 0x33, 0x22, 0x11, // req_id = 0x11223344
        0x37, 0x00, 0x00, 0x00, // len = 55
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // seq
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, // session_id
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, // session_id
        0x02, // stream
        0x03, 0x00, 0x00, 0x00, // chunk_index = 3
        0x04, 0x00, 0x00, 0x00, // total_chunks = 4
        0x00, 0x2a, // alg, kid
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // nonce
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // tag
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // tag
    ];

    /// Golden frame 3: plain `HELLO` with an 18-byte control prefix.
    const GOLDEN_HELLO: [u8; 44] = [
        0x53, 0x01, 0x01, 0x20, 0x00, // magic, ver, type, flags = CTRL
        0x00, 0x00, 0x00, 0x00, // req_id
        0x17, 0x00, 0x00, 0x00, // len = 23
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // seq
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // applied_seq
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, // epoch_seen
        0x00, 0x00, // reserved
        0x01, 0x02, 0x00, 0x01, 0x00, // F_WCP_VER = 1
    ];

    fn golden_welcome() -> FrameBuf {
        FrameBuf::new(
            FrameHeader {
                ver: 1,
                msg_type: MsgType::WELCOME,
                flags: Flags::EMPTY,
                req_id: 0,
                len: 5,
                seq: Seq::UNSEQUENCED,
            },
            Prefix::None,
            vec![0x01, 0x02, 0x00, 0x01, 0x00],
        )
    }

    fn golden_relay() -> FrameBuf {
        FrameBuf::new(
            FrameHeader {
                ver: 1,
                msg_type: MsgType::RELAY,
                flags: Flags::ENC.with(Flags::ROUTED),
                req_id: 0x1122_3344,
                len: 55,
                seq: Seq(0x0102_0304_0506_0708),
            },
            Prefix::Route(RoutePrefix::new(
                SessionId(0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0f),
                StreamId(0x02),
                3,
                4,
            )),
            vec![
                0x00, 0x2a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
        )
    }

    fn golden_hello() -> FrameBuf {
        FrameBuf::new(
            FrameHeader {
                ver: 1,
                msg_type: MsgType::HELLO,
                flags: Flags::CTRL,
                req_id: 0,
                len: 23,
                seq: Seq::UNSEQUENCED,
            },
            Prefix::Ctrl(CtrlPrefix::new(
                Seq(0x0102_0304_0506_0708),
                0x1112_1314_1516_1718,
            )),
            vec![0x01, 0x02, 0x00, 0x01, 0x00],
        )
    }

    #[test]
    fn widths_are_the_arithmetic_sum() {
        assert_eq!(HEADER_LEN, 21);
        assert_eq!(ROUTE_PREFIX_LEN, 25);
        assert_eq!(CTRL_PREFIX_LEN, 18);
        assert_eq!(HEADER_LEN, 1 + 1 + 1 + 2 + 4 + 4 + 8);
        assert_eq!(ROUTE_PREFIX_LEN, 16 + 1 + 4 + 4);
        assert_eq!(CTRL_PREFIX_LEN, 8 + 8 + 2);
    }

    #[test]
    fn golden_header_bytes_are_exact() {
        let welcome = golden_welcome();
        assert_eq!(welcome.header.encode(), GOLDEN_WELCOME[..21]);
        let relay = golden_relay();
        assert_eq!(relay.header.encode(), GOLDEN_RELAY[..21]);
        let hello = golden_hello();
        assert_eq!(hello.header.encode(), GOLDEN_HELLO[..21]);
    }

    #[test]
    fn golden_prefix_bytes_are_exact() {
        assert_eq!(
            golden_relay().prefix,
            Prefix::Route(RoutePrefix::decode(&GOLDEN_RELAY[21..46]).unwrap())
        );
        assert_eq!(
            golden_hello().prefix,
            Prefix::Ctrl(CtrlPrefix::decode(&GOLDEN_HELLO[21..39]).unwrap())
        );
        assert_eq!(
            GOLDEN_RELAY[21..46].to_vec(),
            encode_prefix(&golden_relay().prefix)
        );
        assert_eq!(
            GOLDEN_HELLO[21..39].to_vec(),
            encode_prefix(&golden_hello().prefix)
        );
    }

    #[test]
    fn golden_bodies_are_exact() {
        assert_eq!(golden_welcome().body, GOLDEN_WELCOME[21..]);
        assert_eq!(golden_relay().body, GOLDEN_RELAY[46..]);
        assert_eq!(golden_hello().body, GOLDEN_HELLO[39..]);
    }

    #[test]
    fn header_decode_roundtrips_golden_headers() {
        for golden in [
            &GOLDEN_WELCOME[..21],
            &GOLDEN_RELAY[..21],
            &GOLDEN_HELLO[..21],
        ] {
            let header = FrameHeader::decode(golden).expect("golden header decodes");
            assert_eq!(&header.encode(), golden);
        }
    }

    #[test]
    fn header_decode_rejects_bad_magic() {
        let mut bytes = GOLDEN_WELCOME;
        bytes[0] = 0x52;
        assert_eq!(
            FrameHeader::decode(&bytes).unwrap_err().to_string(),
            "bad magic 0x52, expected 0x53"
        );
    }

    #[test]
    fn header_decode_rejects_unknown_version() {
        let mut bytes = GOLDEN_WELCOME;
        bytes[1] = 2;
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::UnsupportedFrameVer(2))
        ));
    }

    #[test]
    fn header_decode_rejects_unknown_type() {
        let mut bytes = GOLDEN_WELCOME;
        bytes[2] = 0x7f;
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::UnknownType(0x7f))
        ));
    }

    #[test]
    fn header_decode_rejects_reserved_flag_bits() {
        let mut bytes = GOLDEN_WELCOME;
        bytes[3] = 0x40;
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::ReservedFlags(0x0040))
        ));

        // Both reserved bits, separately and together.
        for bits in [0x0080u16, 0x00c0] {
            let mut bytes = GOLDEN_WELCOME;
            bytes[3..5].copy_from_slice(&bits.to_le_bytes());
            assert!(matches!(
                FrameHeader::decode(&bytes),
                Err(ProtocolError::ReservedFlags(got)) if got == bits
            ));
        }
    }

    #[test]
    fn header_decode_accepts_defined_optional_flags() {
        let mut bytes = GOLDEN_RELAY;
        // URGENT | COMPRESSED | FIN on top of ENC | ROUTED.
        bytes[3] = 0x1f;
        let header = FrameHeader::decode(&bytes).expect("defined flags are legal");
        assert!(header.flags.contains(Flags::URGENT));
        assert!(header.flags.contains(Flags::COMPRESSED));
        assert!(header.flags.contains(Flags::FIN));
    }

    #[test]
    fn header_decode_rejects_both_prefix_bits() {
        let mut bytes = GOLDEN_RELAY;
        bytes[3] = 0x38;
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::FlagsConflict(0x0038))
        ));
    }

    #[test]
    fn header_decode_rejects_enc_mismatch() {
        // HELLO is plain, so ENC must be zero.
        let mut bytes = GOLDEN_HELLO;
        bytes[3] = 0x28;
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::FlagsConflict(0x0028))
        ));

        // ORDERED is sealed, so ENC must be one.
        let mut ordered = GOLDEN_WELCOME;
        ordered[2] = 0x10;
        ordered[3] = 0x00;
        assert!(matches!(
            FrameHeader::decode(&ordered),
            Err(ProtocolError::FlagsConflict(0x0000))
        ));
    }

    #[test]
    fn header_decode_rejects_prefix_where_type_forbids_it() {
        let mut bytes = GOLDEN_WELCOME;
        bytes[3] = 0x10; // ROUTED on WELCOME
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(ProtocolError::UnexpectedPrefix)
        ));
    }

    #[test]
    fn with_seq_changes_only_the_seq_bytes() {
        let header = golden_relay().header;
        let moved = header.with_seq(Seq(0xdead_beef));
        let before = header.encode();
        let after = moved.encode();
        for index in 0..HEADER_LEN {
            if (13..21).contains(&index) {
                assert_ne!(before[index], after[index], "seq byte {index} changed");
            } else {
                assert_eq!(before[index], after[index], "byte {index} must not move");
            }
        }
        assert_eq!(moved.seq, Seq(0xdead_beef));
    }

    #[test]
    fn type_table_is_consistent() {
        for msg_type in MsgType::ALL {
            assert!(matches!(
                MsgType::from_u8(msg_type.get()),
                Ok(got) if got == msg_type
            ));
            assert!(MsgType::is_known_raw(msg_type.get()));
            let encoding = msg_type.body_encoding();
            let prefix = msg_type.prefix_kind();
            let mut flags = Flags::EMPTY;
            if encoding.is_sealed() {
                flags = flags.with(Flags::ENC);
            }
            match prefix {
                PrefixKind::Route => flags = flags.with(Flags::ROUTED),
                PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
                PrefixKind::None => {}
            }
            flags.validate(msg_type).expect("table-consistent flags");
        }
        assert!(matches!(
            MsgType::from_u8(0x00),
            Err(ProtocolError::UnknownType(0))
        ));
        assert!(matches!(
            MsgType::from_u8(0x1c),
            Err(ProtocolError::UnknownType(0x1c))
        ));
    }

    #[test]
    fn frame_table_is_exactly_the_psk_table() {
        for msg_type in [MsgType::HELLO, MsgType::WELCOME, MsgType::ERROR] {
            assert_eq!(
                msg_type.body_encoding(),
                BodyEncoding::Plain,
                "{} must stay plain",
                msg_type.name()
            );
        }
        for msg_type in [
            MsgType::AUTH,
            MsgType::ACCEPT,
            MsgType::ORDERED,
            MsgType::RESPONSE,
            MsgType::RELAY,
            MsgType::ACK,
            MsgType::PING,
            MsgType::PONG,
            MsgType::KICK,
            MsgType::FLOW,
            MsgType::SYNC_END,
            MsgType::STREAM_DATA,
            MsgType::LEAVE,
        ] {
            assert_eq!(
                msg_type.body_encoding(),
                BodyEncoding::Sealed,
                "{} must be sealed",
                msg_type.name()
            );
            let mut flags = Flags::EMPTY.with(Flags::ENC);
            match msg_type.prefix_kind() {
                PrefixKind::Route => flags = flags.with(Flags::ROUTED),
                PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
                PrefixKind::None => {}
            }
            flags.validate(msg_type).expect("sealed flags are valid");
            assert!(Flags::EMPTY.validate(msg_type).is_err());
        }
        assert_eq!(MsgType::ALL.len(), 16);
        assert_eq!(MsgType::AUTH.get(), 0x03);
        assert_eq!(MsgType::ACCEPT.get(), 0x04);
        assert_eq!(MsgType::AUTH.name(), "AUTH");
        assert_eq!(MsgType::ACCEPT.name(), "ACCEPT");
    }

    #[test]
    fn len_bounds_use_prefix_and_minimum_body() {
        let limits = Limits::default();
        let header = FrameHeader {
            len: 29,
            ..golden_relay().header
        };
        assert!(matches!(
            header.validate_len(&limits),
            Err(ProtocolError::BodyTooShort {
                len: 29,
                prefix: 25,
                min_body: 30
            })
        ));

        let header = FrameHeader {
            len: 30,
            ..golden_welcome().header
        };
        assert!(header.validate_len(&limits).is_ok());

        let header = FrameHeader {
            len: 2,
            ..golden_welcome().header
        };
        assert!(matches!(
            header.validate_len(&limits),
            Err(ProtocolError::BodyTooShort {
                len: 2,
                prefix: 0,
                min_body: 3
            })
        ));
    }

    #[test]
    fn limits_reject_values_that_describe_no_frame() {
        let too_small = Limits {
            ingress_frame: 50,
            ..Limits::default()
        };
        assert!(matches!(
            too_small.validate(),
            Err(ProtocolError::InvalidLimits { .. })
        ));
        let too_large = Limits {
            ingress_frame: FRAME_MAX + 1,
            ..Limits::default()
        };
        assert!(matches!(
            too_large.validate(),
            Err(ProtocolError::InvalidLimits { .. })
        ));
        assert!(Limits::default().validate().is_ok());
        assert!(Limits::protocol().validate().is_ok());
    }

    #[test]
    fn route_prefix_roundtrips() {
        let prefix = RoutePrefix::new(
            SessionId(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff),
            StreamId::BLOCK,
            7,
            9,
        );
        let bytes = prefix.encode();
        assert_eq!(bytes.len(), ROUTE_PREFIX_LEN);
        assert!(matches!(RoutePrefix::decode(&bytes), Ok(got) if got == prefix));
        assert!(prefix.check_chunk_bounds().is_ok());
    }

    #[test]
    fn route_prefix_rejects_short_and_long_input() {
        assert!(matches!(
            RoutePrefix::decode(&[0u8; ROUTE_PREFIX_LEN - 1]),
            Err(ProtocolError::Truncated { need: 25, got: 24 })
        ));
        assert!(matches!(
            RoutePrefix::decode(&[0u8; ROUTE_PREFIX_LEN + 1]),
            Err(ProtocolError::Truncated { need: 25, got: 26 })
        ));
    }

    #[test]
    fn route_prefix_chunk_bounds() {
        let ok = RoutePrefix::new(SessionId::ZERO, StreamId::BLOCK, 3, 4);
        assert!(ok.check_chunk_bounds().is_ok());
        let control = RoutePrefix::new(SessionId::ZERO, StreamId::CTRL, 0, 0);
        assert!(control.check_chunk_bounds().is_ok());
        let bad_control = RoutePrefix::new(SessionId::ZERO, StreamId::CTRL, 1, 0);
        assert!(matches!(
            bad_control.check_chunk_bounds(),
            Err(ProtocolError::BadChunkBounds { .. })
        ));
        let out_of_range = RoutePrefix::new(SessionId::ZERO, StreamId::BLOCK, 4, 4);
        assert!(matches!(
            out_of_range.check_chunk_bounds(),
            Err(ProtocolError::BadChunkBounds { .. })
        ));
        let too_many = RoutePrefix::new(SessionId::ZERO, StreamId::BLOCK, 0, MAX_CHUNKS + 1);
        assert!(matches!(
            too_many.check_chunk_bounds(),
            Err(ProtocolError::BadChunkBounds { .. })
        ));
    }

    #[test]
    fn ctrl_prefix_roundtrips_and_validates_reserved() {
        let prefix = CtrlPrefix::new(Seq(42), 0xfeed_face_dead_beef);
        let bytes = prefix.encode();
        assert_eq!(bytes.len(), CTRL_PREFIX_LEN);
        assert!(matches!(CtrlPrefix::decode(&bytes), Ok(got) if got == prefix));
        assert!(prefix.validate().is_ok());

        let mut dirty = prefix;
        dirty.reserved = 1;
        assert!(matches!(
            dirty.validate(),
            Err(ProtocolError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn prefix_decode_rejects_width_mismatch() {
        assert!(matches!(
            Prefix::decode(PrefixKind::None, &[0u8; 1]),
            Err(ProtocolError::UnexpectedPrefix)
        ));
        assert!(matches!(
            Prefix::decode(PrefixKind::None, &[]),
            Ok(Prefix::None)
        ));
        assert!(Prefix::decode(PrefixKind::Route, &[0u8; 18]).is_err());
        assert!(Prefix::decode(PrefixKind::Ctrl, &[0u8; 25]).is_err());
    }

    #[test]
    fn prefix_decode_rejects_nonzero_ctrl_reserved() {
        let mut bytes = CtrlPrefix::new(Seq(1), 2).encode();
        bytes[16] = 0x01;
        assert!(matches!(
            Prefix::decode(PrefixKind::Ctrl, &bytes),
            Err(ProtocolError::NonZeroReserved(1))
        ));

        // The field decoder itself stays lossless; the frame-level entry is
        // where the invariant is enforced.
        let ctrl = CtrlPrefix::decode(&bytes).expect("field decode preserves bytes");
        assert_eq!(ctrl.reserved, 1);
        assert!(matches!(
            ctrl.validate(),
            Err(ProtocolError::NonZeroReserved(1))
        ));
    }

    #[test]
    fn identifiers_display_as_hex() {
        let client = ClientId::from_bytes([0xab; 16]);
        assert_eq!(client.to_string(), "ab".repeat(16));
        let op = OpId::from_bytes([0x01; 16]);
        assert_eq!(op.to_string(), "01".repeat(16));
        let session = SessionId(0x0f);
        assert_eq!(session.to_string(), "0000000000000000000000000000000f");
    }

    #[test]
    fn seq_semantics() {
        assert!(!Seq::UNSEQUENCED.is_sequenced());
        assert!(Seq::FIRST.is_sequenced());
        assert_eq!(Seq(1).checked_next(), Some(Seq(2)));
        assert_eq!(Seq(u64::MAX).checked_next(), None);
    }

    fn encode_prefix(prefix: &Prefix) -> Vec<u8> {
        let mut out = Vec::new();
        prefix.encode_into(&mut out);
        out
    }
}
