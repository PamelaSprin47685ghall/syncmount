//! HELLO, session keys and per-request MAC verification.
//!
//! The session lives in memory; a server restart invalidates every session and
//! the client sends a new HELLO. Request bodies are hashed while they stream,
//! so a MAC is always verified over the bytes that were actually received.

use std::sync::PoisonError;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mmap::proto::{
    ErrorCode, Hello, MacParts, SessionGuard, SessionKeys, Welcome, decode_frame, derive_hello_key,
    derive_session_key, encode_frame, parse_mac, parse_seq, parse_session_id, verify_hello,
    welcome_proof,
};

use super::http::{Credentials, ReceivedFrame};
use super::{Fault, ServerState, Session, SessionInfo, now_u64};

impl ServerState {
    /// Process one unauthenticated `HELLO` frame.
    pub fn hello(&self, received: &ReceivedFrame) -> Result<super::http::Response, Fault> {
        let hello: Hello = decode_frame(&received.header, &received.meta)?;
        let now = now_u64();
        {
            let mut guard = self.nonces.lock().unwrap_or_else(PoisonError::into_inner);
            verify_hello(&hello, now, &self.hello_key(), &mut guard)?;
        }

        let session_id = random_nonzero_16();
        let server_nonce = rand::random::<[u8; 32]>();
        let expires = now.saturating_add(self.config().session_ttl_ms);
        self.insert_session(
            session_id,
            hello.client_id,
            derive_session_key(
                &self.config().master_key,
                &hello.client_nonce,
                &server_nonce,
                &session_id,
            ),
            expires,
        )?;

        let welcome = Welcome {
            session_id,
            server_nonce,
            session_expires_at_ms: expires,
            limits: self.config().limits,
            proof: welcome_proof(
                &derive_hello_key(&self.config().master_key),
                &hello.client_nonce,
                &server_nonce,
                &session_id,
                expires,
            ),
        };
        let (header, meta) = encode_frame(&welcome, &self.config().limits)?;
        let mut bytes = Vec::with_capacity(24 + meta.len());
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&meta);
        Ok(super::http::full_response(200, bytes))
    }

    fn hello_key(&self) -> [u8; 32] {
        derive_hello_key(&self.config().master_key)
    }

    fn insert_session(
        &self,
        session_id: [u8; 16],
        client_id: [u8; 16],
        key: [u8; 32],
        expires_ms: u64,
    ) -> Result<(), Fault> {
        let now = super::now_ms();
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let ttl = self.config().session_ttl_ms as i64;
        sessions.retain(|_, session| {
            session.guard.expires_at_ms() >= now_u64()
                && now.saturating_sub(session.last_seen_ms) <= ttl
        });
        if sessions.len() >= self.config().max_sessions {
            return Err(Fault::detail(ErrorCode::Busy, "session table is full"));
        }
        sessions.insert(
            session_id,
            Session {
                client_id,
                keys: SessionKeys::new(key, session_id, expires_ms),
                guard: SessionGuard::new(expires_ms),
                last_seen_ms: now,
            },
        );
        Ok(())
    }

    /// Verify a POST request after its body has been received.
    pub fn authenticate_frame(
        &self,
        method: &str,
        path: &str,
        credentials: &Credentials,
        received: &ReceivedFrame,
    ) -> Result<SessionInfo, Fault> {
        self.authenticate(
            method,
            path,
            credentials,
            received.meta_hash,
            received.payload_hash,
        )
    }

    /// Verify a GET request, whose meta and payload are empty.
    pub fn authenticate_empty(
        &self,
        method: &str,
        path: &str,
        credentials: &Credentials,
    ) -> Result<SessionInfo, Fault> {
        let empty = *blake3::hash(b"").as_bytes();
        self.authenticate(method, path, credentials, empty, empty)
    }

    fn authenticate(
        &self,
        method: &str,
        path: &str,
        credentials: &Credentials,
        meta_hash: [u8; 32],
        payload_hash: [u8; 32],
    ) -> Result<SessionInfo, Fault> {
        let session_text = credentials
            .session
            .as_deref()
            .ok_or_else(|| Fault::detail(ErrorCode::AuthFailed, "missing session header"))?;
        let seq_text = credentials
            .seq
            .as_deref()
            .ok_or_else(|| Fault::detail(ErrorCode::AuthFailed, "missing sequence header"))?;
        let mac_text = credentials
            .mac
            .as_deref()
            .ok_or_else(|| Fault::detail(ErrorCode::AuthFailed, "missing MAC header"))?;
        let session_id = parse_session_id(session_text)?;
        let seq = parse_seq(seq_text)
            .map_err(|_| Fault::detail(ErrorCode::BadRequest, "bad sequence"))?;
        let mac = parse_mac(mac_text)?;

        let now = super::now_ms();
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(session) = sessions.get_mut(&session_id) else {
            return Err(Fault::detail(ErrorCode::SessionExpired, "unknown session"));
        };
        if now.saturating_sub(session.last_seen_ms) > self.config().session_ttl_ms as i64 {
            sessions.remove(&session_id);
            return Err(Fault::detail(
                ErrorCode::SessionExpired,
                "idle session expired",
            ));
        }
        let parts = MacParts {
            method,
            path,
            seq,
            meta_hash,
            payload_hash,
        };
        session
            .guard
            .verify(&session.keys, &parts, &mac, now_u64())
            .map_err(Fault::from)?;
        session.last_seen_ms = now;
        Ok(SessionInfo {
            client_id: session.client_id,
            session_id,
        })
    }
}

fn random_nonzero_16() -> [u8; 16] {
    loop {
        let bytes = rand::random::<[u8; 16]>();
        if bytes != [0u8; 16] {
            return bytes;
        }
    }
}

/// A fresh timestamp, exposed so a future client and the server tests derive
/// HELLO proofs from one clock.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
