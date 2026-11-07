//! Endpoint derivation: URL → two stream URIs, headers, nonce pairing.
//!
//! The URL a user writes is a **path prefix**, never a single resource
//! (24 §1). `http://host:8080/team-a/sync` derives exactly two sync paths:
//!
//! ```text
//! POST /team-a/sync/rpc      uplink, chunked request body
//! GET  /team-a/sync/events   downlink, chunked response body
//! ```
//!
//! A root prefix (`http://host/`, or no path at all) degenerates to `/rpc`
//! and `/events`. The management path is always absolute and prefix-free:
//! `/__syncmount/healthz`.
//!
//! Two streams of one logical session are paired by the `X-SM-Nonce` header,
//! **never by source address** (42 §7.3): behind NAT several clients share an
//! IP, and the two streams may arrive in any order from any source port.
//! [`PairingTable`] is the server-side state machine for that rule. The
//! nonce is a random `u64`; it is a rendezvous token, not a credential.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use http::header::{HeaderMap, HeaderValue};
use http::uri::{Authority, PathAndQuery, Scheme as UriScheme, Uri};

/// Absolute management endpoint. Authentication-exempt by design.
pub const HEALTHZ_PATH: &str = "/__syncmount/healthz";

/// Suffix appended to the namespace for the uplink.
pub const RPC_SUFFIX: &str = "/rpc";

/// Suffix appended to the namespace for the downlink.
pub const EVENTS_SUFFIX: &str = "/events";

/// Header that pairs the uplink and downlink of one session.
pub const NONCE_HEADER: &str = "x-sm-nonce";

/// Header that carries the client id declaration (never a credential).
pub const CLIENT_ID_HEADER: &str = "x-sm-client-id";

/// How long an unclaimed downlink may wait for its uplink (42 §7.3).
pub const PAIR_TIMEOUT: Duration = Duration::from_secs(10);

/// Transport scheme. TLS termination is a deployment concern (24 §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// HTTPS. Parsed for completeness; the v1 dialer refuses it.
    Https,
}

impl Scheme {
    /// Lower-case wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Port used when the authority omits one.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    /// Whether the scheme requires TLS.
    pub const fn is_tls(self) -> bool {
        matches!(self, Self::Https)
    }

    fn parse(raw: &str) -> Result<Self, EndpointError> {
        if raw.eq_ignore_ascii_case("http") {
            Ok(Self::Http)
        } else if raw.eq_ignore_ascii_case("https") {
            Ok(Self::Https)
        } else {
            Err(EndpointError::UnsupportedScheme(raw.to_owned()))
        }
    }
}

impl From<Scheme> for UriScheme {
    fn from(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Http => UriScheme::HTTP,
            Scheme::Https => UriScheme::HTTPS,
        }
    }
}

/// A parsed endpoint: authority plus a normalized namespace.
///
/// Construction is the only way to obtain one, so an `Endpoint` always has a
/// scheme of `http`/`https`, a non-empty authority, and a namespace without a
/// trailing slash (root is `/`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    uri: Uri,
    authority: Authority,
    rpc: Uri,
    events: Uri,
    healthz: Uri,
    namespace: String,
    scheme: Scheme,
}

impl Endpoint {
    /// Parse and normalize a user-supplied URL.
    ///
    /// Rejects userinfo, query and fragment (24 §7.1), `.`/`..` segments,
    /// empty segments and control characters. Percent escapes are decoded
    /// before segment checks, so `%2F` is a path separator and `%2E%2E` is
    /// still rejected.
    pub fn parse(raw: &str) -> Result<Self, EndpointError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(EndpointError::Empty);
        }
        let (scheme_text, rest) = raw.split_once("://").ok_or(EndpointError::MissingScheme)?;
        let scheme = Scheme::parse(scheme_text)?;
        let (authority_text, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        if authority_text.is_empty() {
            return Err(EndpointError::MissingAuthority);
        }
        if authority_text.contains('@') {
            return Err(EndpointError::UserInfo);
        }
        if path.contains('?') || path.contains('#') {
            return Err(EndpointError::QueryOrFragment);
        }
        let authority = Authority::from_str(authority_text)
            .map_err(|error| EndpointError::Authority(error.to_string()))?;
        if authority.host().is_empty() {
            return Err(EndpointError::MissingAuthority);
        }
        let namespace = normalize_prefix(path)?;

        let base = build_uri(scheme, &authority, &namespace)?;
        let rpc = build_uri(scheme, &authority, &child_path(&namespace, RPC_SUFFIX))?;
        let events = build_uri(scheme, &authority, &child_path(&namespace, EVENTS_SUFFIX))?;
        let healthz = build_uri(scheme, &authority, HEALTHZ_PATH)?;
        Ok(Self {
            uri: base,
            authority,
            rpc,
            events,
            healthz,
            namespace,
            scheme,
        })
    }

    /// Canonical base URL (`scheme://authority/prefix`).
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Normalized namespace. Root is `/`; everything else starts with `/`
    /// and has no trailing slash.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Transport scheme.
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Whether the endpoint asks for TLS.
    pub const fn is_tls(&self) -> bool {
        self.scheme.is_tls()
    }

    /// Authority exactly as written (host plus optional port).
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Host without brackets around IPv6 literals.
    pub fn host(&self) -> &str {
        let host = self.authority.host();
        host.strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host)
    }

    /// Explicit or scheme-default port.
    pub fn port(&self) -> u16 {
        self.authority
            .port_u16()
            .unwrap_or_else(|| self.scheme.default_port())
    }

    /// Uplink URI (`{prefix}/rpc`).
    pub const fn rpc_uri(&self) -> &Uri {
        &self.rpc
    }

    /// Downlink URI (`{prefix}/events`).
    pub const fn events_uri(&self) -> &Uri {
        &self.events
    }

    /// Management URI (`/__syncmount/healthz`).
    pub const fn healthz_uri(&self) -> &Uri {
        &self.healthz
    }
}

pub(crate) fn child_path(namespace: &str, suffix: &str) -> String {
    if namespace == "/" {
        suffix.to_owned()
    } else {
        format!("{namespace}{suffix}")
    }
}

fn build_uri(scheme: Scheme, authority: &Authority, path: &str) -> Result<Uri, EndpointError> {
    let mut parts = http::uri::Parts::default();
    parts.scheme = Some(scheme.into());
    parts.authority = Some(authority.clone());
    parts.path_and_query =
        Some(PathAndQuery::from_str(path).map_err(|error| EndpointError::Path(error.to_string()))?);
    Uri::from_parts(parts).map_err(|error| EndpointError::Path(error.to_string()))
}

/// Normalize a path prefix: strip trailing slashes, decode escapes, reject
/// ambiguous or traversing segments.
///
/// Both `""` and `/` normalize to `/`. A path must be absolute.
pub fn normalize_prefix(path: &str) -> Result<String, EndpointError> {
    let decoded = percent_decode(path)?;
    if decoded.chars().any(char::is_control) {
        return Err(EndpointError::ControlCharacter);
    }
    if decoded.contains('?') || decoded.contains('#') {
        // A decoded `%3F`/`%23` would silently become a query or fragment
        // when the path is rebuilt; refuse instead of guessing.
        return Err(EndpointError::QueryOrFragment);
    }
    let trimmed = decoded.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_owned());
    }
    if !trimmed.starts_with('/') {
        return Err(EndpointError::RelativePath(trimmed.to_owned()));
    }
    let mut normalized = String::with_capacity(trimmed.len());
    for segment in trimmed.split('/').skip(1) {
        if segment.is_empty() {
            return Err(EndpointError::EmptySegment);
        }
        if segment == "." || segment == ".." {
            return Err(EndpointError::ForbiddenSegment(segment.to_owned()));
        }
        normalized.push('/');
        normalized.push_str(segment);
    }
    Ok(normalized)
}

fn percent_decode(path: &str) -> Result<String, EndpointError> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = bytes
                .get(index + 1)
                .copied()
                .and_then(hex_digit)
                .ok_or(EndpointError::PercentEncoding)?;
            let lo = bytes
                .get(index + 2)
                .copied()
                .and_then(hex_digit)
                .ok_or(EndpointError::PercentEncoding)?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_| EndpointError::PercentEncoding)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Build the `X-SM-Nonce` value.
pub fn nonce_header(nonce: u64) -> Result<HeaderValue, EndpointError> {
    HeaderValue::from_str(&nonce.to_string())
        .map_err(|error| EndpointError::Header(error.to_string()))
}

/// Build the `X-SM-Client-Id` value: 32 lower-case hex digits.
pub fn client_id_header(client: [u8; 16]) -> Result<HeaderValue, EndpointError> {
    HeaderValue::from_str(&hex::encode(client))
        .map_err(|error| EndpointError::Header(error.to_string()))
}

/// Read and validate `X-SM-Nonce`.
pub fn nonce_from_headers(headers: &HeaderMap) -> Result<u64, EndpointError> {
    let value = headers
        .get(NONCE_HEADER)
        .ok_or(EndpointError::MissingNonce)?;
    let text = value
        .to_str()
        .map_err(|_| EndpointError::Nonce(String::from("<non-utf8>")))?;
    text.parse::<u64>()
        .map_err(|_| EndpointError::Nonce(text.to_owned()))
}

/// Read `X-SM-Client-Id` when present. Absence is normal on first contact.
pub fn client_id_from_headers(headers: &HeaderMap) -> Result<Option<[u8; 16]>, EndpointError> {
    let Some(value) = headers.get(CLIENT_ID_HEADER) else {
        return Ok(None);
    };
    let text = value
        .to_str()
        .map_err(|_| EndpointError::ClientId(String::from("<non-utf8>")))?;
    let bytes = hex::decode(text).map_err(|_| EndpointError::ClientId(text.to_owned()))?;
    let array: [u8; 16] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EndpointError::ClientId(text.to_owned()))?;
    Ok(Some(array))
}

/// Why a URL or header could not be accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EndpointError {
    /// Input was empty or only whitespace.
    #[error("URL is empty")]
    Empty,
    /// No `://` separator.
    #[error("URL has no scheme; expected http:// or https://")]
    MissingScheme,
    /// Scheme is neither `http` nor `https`.
    #[error("unsupported scheme {0:?}")]
    UnsupportedScheme(String),
    /// No authority component.
    #[error("URL has no authority")]
    MissingAuthority,
    /// `user:password@` is not part of the sync URL grammar.
    #[error("URL must not carry userinfo")]
    UserInfo,
    /// Query or fragment would be silently dropped; reject it.
    #[error("URL must not carry a query or fragment")]
    QueryOrFragment,
    /// Authority failed URI validation.
    #[error("invalid authority: {0}")]
    Authority(String),
    /// Path failed URI validation.
    #[error("invalid path: {0}")]
    Path(String),
    /// Percent escape is truncated or not hexadecimal.
    #[error("invalid percent-encoding in path")]
    PercentEncoding,
    /// Control character in the path.
    #[error("path contains a control character")]
    ControlCharacter,
    /// Prefix does not start with `/`.
    #[error("path prefix {0:?} is not absolute")]
    RelativePath(String),
    /// Two consecutive separators.
    #[error("path contains an empty segment")]
    EmptySegment,
    /// `.` or `..`.
    #[error("path segment {0:?} is not allowed")]
    ForbiddenSegment(String),
    /// Header value could not be built.
    #[error("invalid header value: {0}")]
    Header(String),
    /// `X-SM-Nonce` is absent.
    #[error("missing X-SM-Nonce header")]
    MissingNonce,
    /// `X-SM-Nonce` is not a decimal u64.
    #[error("invalid X-SM-Nonce value {0:?}")]
    Nonce(String),
    /// `X-SM-Client-Id` is not 32 hex digits.
    #[error("invalid X-SM-Client-Id value {0:?}")]
    ClientId(String),
}

/// A downlink parked until its uplink claims it.
#[derive(Debug)]
struct Parked<T> {
    value: T,
    parked_at: Instant,
}

/// Pairing state keyed only by nonce.
///
/// The table never accepts a peer address, which is the point: NAT makes
/// addresses ambiguous, and an address is not an identity. Duplicate nonces
/// are refused so a second downlink cannot steal a pending claim.
#[derive(Debug)]
pub struct PairingTable<T> {
    ttl: Duration,
    pending: HashMap<u64, Parked<T>>,
}

impl<T> PairingTable<T> {
    /// Empty table with an explicit timeout.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            pending: HashMap::new(),
        }
    }

    /// Empty table with [`PAIR_TIMEOUT`].
    pub fn with_default_timeout() -> Self {
        Self::new(PAIR_TIMEOUT)
    }

    /// Park a downlink. Replaces an entry only when that entry has expired.
    pub fn park(&mut self, nonce: u64, value: T, now: Instant) -> Result<(), PairingError> {
        if let Some(existing) = self.pending.get(&nonce) {
            if now.saturating_duration_since(existing.parked_at) < self.ttl {
                return Err(PairingError::DuplicateNonce(nonce));
            }
        }
        self.pending.insert(
            nonce,
            Parked {
                value,
                parked_at: now,
            },
        );
        Ok(())
    }

    /// Claim a fresh parked downlink. Expired entries are dropped, not
    /// returned.
    pub fn claim(&mut self, nonce: u64, now: Instant) -> Option<T> {
        let parked = self.pending.remove(&nonce)?;
        if now.saturating_duration_since(parked.parked_at) < self.ttl {
            Some(parked.value)
        } else {
            None
        }
    }

    /// Drop and return every entry older than the timeout.
    pub fn sweep(&mut self, now: Instant) -> Vec<T> {
        let ttl = self.ttl;
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, parked)| now.saturating_duration_since(parked.parked_at) >= ttl)
            .map(|(nonce, _)| *nonce)
            .collect();
        expired
            .into_iter()
            .filter_map(|nonce| self.pending.remove(&nonce).map(|parked| parked.value))
            .collect()
    }

    /// Number of parked downlinks.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is parked.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Why a downlink could not be parked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// Another live downlink already uses this nonce.
    #[error("nonce {0} is already parked")]
    DuplicateNonce(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(seconds: u64) -> Instant {
        Instant::now() + Duration::from_secs(seconds)
    }

    #[test]
    fn u_endpoint_derives_stream_uris() {
        let endpoint = match Endpoint::parse("http://127.0.0.1:8080/team-a/sync") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("parse failed: {error}"),
        };
        assert_eq!(endpoint.namespace(), "/team-a/sync");
        assert_eq!(endpoint.host(), "127.0.0.1");
        assert_eq!(endpoint.port(), 8080);
        assert_eq!(endpoint.rpc_uri().path(), "/team-a/sync/rpc");
        assert_eq!(endpoint.events_uri().path(), "/team-a/sync/events");
        assert_eq!(endpoint.healthz_uri().path(), HEALTHZ_PATH);
        assert_eq!(endpoint.scheme(), Scheme::Http);
    }

    #[test]
    fn u_endpoint_root_prefix() {
        for raw in [
            "http://example.test",
            "http://example.test/",
            "http://example.test///",
        ] {
            let endpoint = match Endpoint::parse(raw) {
                Ok(endpoint) => endpoint,
                Err(error) => panic!("parse failed for {raw}: {error}"),
            };
            assert_eq!(endpoint.namespace(), "/");
            assert_eq!(endpoint.rpc_uri().path(), "/rpc");
            assert_eq!(endpoint.events_uri().path(), "/events");
            assert_eq!(endpoint.port(), 80);
        }
    }

    #[test]
    fn u_endpoint_normalizes_trailing_slash_and_escapes() {
        let endpoint = match Endpoint::parse("http://host/sync/") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("parse failed: {error}"),
        };
        assert_eq!(endpoint.namespace(), "/sync");
        assert_eq!(endpoint.rpc_uri().path(), "/sync/rpc");

        let endpoint = match Endpoint::parse("http://host/a%2Fb") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("parse failed: {error}"),
        };
        assert_eq!(endpoint.namespace(), "/a/b");
    }

    #[test]
    fn u_endpoint_https_defaults() {
        let endpoint = match Endpoint::parse("https://example.test/sync") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("parse failed: {error}"),
        };
        assert_eq!(endpoint.port(), 443);
        assert!(endpoint.is_tls());
    }

    #[test]
    fn u_endpoint_ipv6_literal() {
        let endpoint = match Endpoint::parse("http://[::1]:8080/sync") {
            Ok(endpoint) => endpoint,
            Err(error) => panic!("parse failed: {error}"),
        };
        assert_eq!(endpoint.host(), "::1");
        assert_eq!(endpoint.port(), 8080);
        assert_eq!(endpoint.rpc_uri().path(), "/sync/rpc");
    }

    #[test]
    fn u_endpoint_rejects_ambiguous_urls() {
        assert!(matches!(
            Endpoint::parse("http://host/sync?token=1"),
            Err(EndpointError::QueryOrFragment)
        ));
        assert!(matches!(
            Endpoint::parse("http://host/sync#frag"),
            Err(EndpointError::QueryOrFragment)
        ));
        assert!(matches!(
            Endpoint::parse("http://user:pass@host/sync"),
            Err(EndpointError::UserInfo)
        ));
        assert!(matches!(
            Endpoint::parse("ftp://host/sync"),
            Err(EndpointError::UnsupportedScheme(_))
        ));
        assert!(matches!(
            Endpoint::parse("host/sync"),
            Err(EndpointError::MissingScheme)
        ));
        assert!(matches!(
            Endpoint::parse("http://host/a/../b"),
            Err(EndpointError::ForbiddenSegment(_))
        ));
        assert!(matches!(
            Endpoint::parse("http://host/a//b"),
            Err(EndpointError::EmptySegment)
        ));
        assert!(matches!(
            Endpoint::parse("http://host/%2e%2e"),
            Err(EndpointError::ForbiddenSegment(_))
        ));
        assert!(matches!(
            Endpoint::parse("http://host/%zz"),
            Err(EndpointError::PercentEncoding)
        ));
        assert!(matches!(
            Endpoint::parse("http:///sync"),
            Err(EndpointError::MissingAuthority)
        ));
    }

    #[test]
    fn u_nonce_and_client_id_headers_roundtrip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            NONCE_HEADER,
            match nonce_header(u64::MAX) {
                Ok(value) => value,
                Err(error) => panic!("nonce header failed: {error}"),
            },
        );
        assert_eq!(nonce_from_headers(&headers), Ok(u64::MAX));

        let id = [0xab; 16];
        headers.insert(
            CLIENT_ID_HEADER,
            match client_id_header(id) {
                Ok(value) => value,
                Err(error) => panic!("client id header failed: {error}"),
            },
        );
        assert_eq!(client_id_from_headers(&headers), Ok(Some(id)));

        headers.remove(NONCE_HEADER);
        assert_eq!(
            nonce_from_headers(&headers),
            Err(EndpointError::MissingNonce)
        );
        assert_eq!(client_id_from_headers(&headers), Ok(Some(id)));
        headers.remove(CLIENT_ID_HEADER);
        assert_eq!(client_id_from_headers(&headers), Ok(None));
    }

    #[test]
    fn u_pairing_uses_nonce_not_peer() {
        let now = instant(0);
        let mut table = PairingTable::with_default_timeout();
        assert!(table.park(7, "downlink", now).is_ok());
        assert_eq!(table.len(), 1);

        // A different nonce, from any source, must not claim it.
        assert_eq!(table.claim(8, now), None);
        assert_eq!(table.len(), 1);

        // The matching nonce claims it, regardless of who asks.
        assert_eq!(table.claim(7, now), Some("downlink"));
        assert!(table.is_empty());
    }

    #[test]
    fn u_pairing_rejects_duplicates_and_expires() {
        let now = instant(0);
        let mut table = PairingTable::new(Duration::from_secs(10));
        assert!(table.park(1, "first", now).is_ok());
        assert_eq!(
            table.park(1, "second", now),
            Err(PairingError::DuplicateNonce(1))
        );
        assert_eq!(table.claim(1, instant(10)), None);
        assert!(table.is_empty());

        assert!(table.park(2, "stale", now).is_ok());
        assert_eq!(table.sweep(instant(11)), vec!["stale"]);
        assert!(table.is_empty());
    }
}
