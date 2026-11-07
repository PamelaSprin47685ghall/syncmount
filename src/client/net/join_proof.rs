//! JOIN_PROOF responder for a client that is still JOINING.
//!
//! The server's relay hub treats a client as a peer as soon as its session is
//! `Online` (both HTTP halves paired), which happens before the client's
//! steady-state replay pump exists. A third client can therefore have its
//! `JOIN_PROOF` routed to a member that is still in `cluster_wins`; that
//! member's [`JoinReader`](crate::client::net::JoinReader) only routes relay
//! frames to the link/backlog and never answers the proof. The joiner then
//! waits forever: no server timer ends a slow join.
//!
//! [`JoinProofResponder`] closes that window: it verifies a `JOIN_PROOF` with
//! the same cluster credentials the steady pump uses and returns the
//! `JOIN_ACCEPT`/`JOIN_FAIL` frame. The caller writes it through
//! [`RelaySyncLink::send_frame`](crate::client::sync_link::RelaySyncLink::send_frame),
//! which uses the JOINING scoped writer, so the single-writer rule holds.
//!
//! There is no peer-side relay session to establish: the server forwards the
//! first `RELAY{CTRL,0,0}` frame itself (see `SequencerCore::on_relay`), and
//! the client already routes `RELAY`/`STREAM_DATA` by frame type. The only
//! missing piece is answering the proof while the pump is not running yet.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use crate::client::sync_link::seal_relay;
use crate::client::{
    KEY_ENTRY_LEN, PROOF_RESULT_KEY_MISMATCH, PROOF_RESULT_KEY_REJECTED, PROOF_RESULT_PROOF_INVALID,
};
use crate::crypto::proof::Proof;
use crate::crypto::secret::MasterKey;
use crate::crypto::sign::SigningKey;
use crate::protocol::crypto::{ClusterId, KeyRing, NonceMinter, Opener};
use crate::protocol::identity::{KeyAnnounce, KeyDirectory, KeyEpoch, PublicKey, Signature};
use crate::protocol::messages::{RelaySub, WcpError, WcpWriter, fid};
use crate::protocol::{ClientId, FrameBuf, Limits, Message, MsgType, StreamId, decode_sealed};

/// Verifies `JOIN_PROOF` and builds the matching answer.
pub struct JoinProofResponder {
    master: Arc<MasterKey>,
    signing: Arc<SigningKey>,
    ring: Arc<KeyRing>,
    keys: Arc<Mutex<KeyDirectory>>,
    cluster: ClusterId,
    nonces: NonceMinter,
}

impl fmt::Debug for JoinProofResponder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinProofResponder")
            .field("client_id", &self.signing.client_id())
            .field("key_epoch", &self.signing.key_epoch())
            .field("keys", &self.keys.lock().map_or(0, |keys| keys.len()))
            .finish_non_exhaustive()
    }
}

impl JoinProofResponder {
    /// Bind the cluster credentials and the key directory.
    pub fn new(
        master: Arc<MasterKey>,
        signing: Arc<SigningKey>,
        ring: Arc<KeyRing>,
        keys: Arc<Mutex<KeyDirectory>>,
        cluster: ClusterId,
    ) -> Self {
        Self {
            master,
            signing,
            ring,
            keys,
            cluster,
            nonces: NonceMinter::with_instance(rand::random::<u64>()),
        }
    }

    /// Answer one incoming `RELAY{CTRL, JOIN_PROOF}` frame.
    ///
    /// Returns `None` when the frame is not a proof this client can read.
    /// A malformed proof is answered with `JOIN_FAIL`, never ignored: the
    /// joiner needs a verdict to fail closed.
    pub fn answer(&self, frame: &FrameBuf) -> Option<FrameBuf> {
        let route = frame.prefix.as_route()?;
        if route.stream != StreamId::CTRL || route.chunk_index != 0 || route.total_chunks != 0 {
            return None;
        }
        let plaintext = Opener::new(self.ring.as_ref())
            .open(&frame.header, &frame.prefix, &frame.body)
            .ok()?;
        let Message::Relay(relay) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default()).ok()?
        else {
            return None;
        };
        if relay.sub != RelaySub::JoinProof {
            return None;
        }
        let client_nonce = relay.fields.fixed::<32>(fid::F_CLIENT_NONCE).ok()??;
        let server_nonce = relay.fields.fixed::<32>(fid::F_SERVER_NONCE).ok()??;
        let sealed = relay.fields.get(fid::F_PROOF)?;
        let mut announced = relay
            .fields
            .get(fid::F_KEY_ENTRIES)
            .and_then(decode_key_entries)?;
        if announced.len() != 1 {
            return None;
        }
        let announced = announced.pop()?;

        let own = KeyAnnounce::sign(
            self.signing.as_ref(),
            &self.cluster,
            self.signing.key_epoch(),
            None,
        );
        let (result, entries) = {
            let mut directory = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = directory.trust(&own);
            match Proof::open(
                self.master.as_ref(),
                &self.cluster,
                &client_nonce,
                &server_nonce,
                sealed,
            ) {
                Ok(proof)
                    if proof.client_id() == announced.client
                        && proof.public_key() == announced.public.as_bytes() =>
                {
                    match directory.trust(&announced) {
                        Ok(_) => (
                            0u8,
                            directory
                                .iter()
                                .map(|entry| KeyAnnounce {
                                    client: entry.client,
                                    epoch: entry.epoch,
                                    public: entry.public,
                                    self_sig: entry.self_sig,
                                    prev_sig: None,
                                })
                                .collect::<Vec<_>>(),
                        ),
                        Err(_) => (PROOF_RESULT_KEY_REJECTED, Vec::new()),
                    }
                }
                Ok(_) => (PROOF_RESULT_KEY_MISMATCH, Vec::new()),
                Err(_) => (PROOF_RESULT_PROOF_INVALID, Vec::new()),
            }
        };
        let body = if result == 0 {
            encode_join_accept(&entries).ok()?
        } else {
            encode_join_fail(result).ok()?
        };
        seal_relay(self.ring.as_ref(), &self.nonces, route.session_id, &body).ok()
    }
}

/// `RELAY{CTRL, JOIN_ACCEPT}` body: every key the verifier knows.
fn encode_join_accept(entries: &[KeyAnnounce]) -> Result<Vec<u8>, WcpError> {
    let mut writer = WcpWriter::new();
    writer.u8(fid::F_SUB_KIND, RelaySub::JoinAccept.as_u8());
    writer.bytes(fid::F_KEY_ENTRIES, &encode_key_entries(entries));
    writer.finish()
}

/// `RELAY{CTRL, JOIN_FAIL}` body: why the proof was refused.
fn encode_join_fail(result: u8) -> Result<Vec<u8>, WcpError> {
    let mut writer = WcpWriter::new();
    writer.u8(fid::F_SUB_KIND, RelaySub::JoinFail.as_u8());
    writer.u8(fid::F_PROOF_RESULT, result);
    writer.finish()
}

/// Serialize key entries in the fixed [`KEY_ENTRY_LEN`] record layout.
fn encode_key_entries(entries: &[KeyAnnounce]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * KEY_ENTRY_LEN);
    for entry in entries {
        out.extend_from_slice(entry.client.as_bytes());
        out.extend_from_slice(&entry.epoch.get().to_le_bytes());
        out.extend_from_slice(entry.public.as_bytes());
        out.extend_from_slice(entry.self_sig.as_bytes());
    }
    out
}

/// Parse [`encode_key_entries`] output. The binding is checked later by
/// [`KeyDirectory::trust`], never here.
fn decode_key_entries(bytes: &[u8]) -> Option<Vec<KeyAnnounce>> {
    if bytes.len() % KEY_ENTRY_LEN != 0 {
        return None;
    }
    let mut entries = Vec::with_capacity(bytes.len() / KEY_ENTRY_LEN);
    for chunk in bytes.chunks_exact(KEY_ENTRY_LEN) {
        let mut client = [0u8; ClientId::LEN];
        client.copy_from_slice(&chunk[..ClientId::LEN]);
        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&chunk[ClientId::LEN..ClientId::LEN + 4]);
        let public =
            PublicKey::from_slice(&chunk[ClientId::LEN + 4..ClientId::LEN + 4 + PublicKey::LEN])
                .ok()?;
        let self_sig = Signature::from_slice(&chunk[ClientId::LEN + 4 + PublicKey::LEN..]).ok()?;
        entries.push(KeyAnnounce {
            client: ClientId::from_bytes(client),
            epoch: KeyEpoch(u32::from_le_bytes(epoch)),
            public,
            self_sig,
            prev_sig: None,
        });
    }
    Some(entries)
}

/// True for a `JOIN_PROOF` body this responder handles (tests/diagnostics).
pub fn is_join_proof(frame: &FrameBuf, ring: &KeyRing) -> bool {
    let Some(route) = frame.prefix.as_route() else {
        return false;
    };
    if route.stream != StreamId::CTRL {
        return false;
    }
    let Ok(plaintext) = Opener::new(ring).open(&frame.header, &frame.prefix, &frame.body) else {
        return false;
    };
    matches!(
        decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default()),
        Ok(Message::Relay(relay)) if relay.sub == RelaySub::JoinProof
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::protocol::ProtoVersion;
    use crate::protocol::crypto::KeyRing;
    use crate::protocol::crypto::Opener;
    use crate::protocol::{SessionId, decode_sealed};

    fn cluster() -> ClusterId {
        ClusterId::from_bytes([9u8; 16])
    }

    fn proof_frame(
        master: &MasterKey,
        signing: &SigningKey,
        ring: &KeyRing,
        session: SessionId,
    ) -> FrameBuf {
        let client_nonce = [0x11; 32];
        let server_nonce = [0x22; 32];
        let proof = Proof::new(
            signing,
            client_nonce,
            server_nonce,
            7,
            ProtoVersion::CURRENT,
        );
        let sealed = proof.seal(master, &cluster()).expect("seal proof");
        let own = KeyAnnounce::sign(signing, &cluster(), signing.key_epoch(), None);
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::JoinProof.as_u8());
        writer.bytes(fid::F_CLIENT_NONCE, &client_nonce);
        writer.bytes(fid::F_SERVER_NONCE, &server_nonce);
        writer.bytes(fid::F_PROOF, &sealed);
        writer.bytes(fid::F_KEY_ENTRIES, &encode_key_entries(&[own]));
        let body = writer.finish().expect("proof body");
        seal_relay(ring, &NonceMinter::with_instance(1), session, &body).expect("frame")
    }

    #[test]
    fn u_join_proof_responder_accepts_a_valid_proof() {
        let cluster = cluster();
        let master =
            Arc::new(MasterKey::derive_from_password(b"responder-test", &cluster).expect("master"));
        let signing = Arc::new(SigningKey::from_seed(&cluster, [0x41; 32]));
        let ring = Arc::new(KeyRing::derive(&[7u8; 32], &cluster).expect("ring"));
        let keys = Arc::new(Mutex::new(KeyDirectory::new(cluster)));
        let responder = JoinProofResponder::new(
            Arc::clone(&master),
            Arc::clone(&signing),
            Arc::clone(&ring),
            Arc::clone(&keys),
            cluster,
        );
        let session = SessionId::new(0x7001);
        let frame = proof_frame(master.as_ref(), signing.as_ref(), ring.as_ref(), session);
        let reply = responder.answer(&frame).expect("answer");
        let plaintext = Opener::new(ring.as_ref())
            .open(&reply.header, &reply.prefix, &reply.body)
            .expect("open reply");
        let Message::Relay(relay) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default())
                .expect("reply relay")
        else {
            panic!("not a relay");
        };
        assert_eq!(relay.sub, RelaySub::JoinAccept);
        let entries = relay.fields.get(fid::F_KEY_ENTRIES).expect("entries");
        assert_eq!(entries.len(), KEY_ENTRY_LEN);
        assert_eq!(reply.prefix.as_route().expect("route").session_id, session);
    }

    #[test]
    fn u_join_proof_responder_rejects_a_foreign_proof() {
        let cluster = cluster();
        let master =
            Arc::new(MasterKey::derive_from_password(b"responder-test", &cluster).expect("master"));
        let wrong = Arc::new(
            MasterKey::derive_from_password(b"other-master", &cluster).expect("wrong master"),
        );
        let signing = Arc::new(SigningKey::from_seed(&cluster, [0x42; 32]));
        let ring = Arc::new(KeyRing::derive(&[7u8; 32], &cluster).expect("ring"));
        let keys = Arc::new(Mutex::new(KeyDirectory::new(cluster)));
        let responder = JoinProofResponder::new(
            Arc::clone(&master),
            Arc::clone(&signing),
            Arc::clone(&ring),
            keys,
            cluster,
        );
        let session = SessionId::new(0x7002);
        let frame = proof_frame(wrong.as_ref(), signing.as_ref(), ring.as_ref(), session);
        let reply = responder.answer(&frame).expect("answer");
        let plaintext = Opener::new(ring.as_ref())
            .open(&reply.header, &reply.prefix, &reply.body)
            .expect("open reply");
        let Message::Relay(relay) =
            decode_sealed(MsgType::RELAY, plaintext.as_slice(), &Limits::default())
                .expect("reply relay")
        else {
            panic!("not a relay");
        };
        assert_eq!(relay.sub, RelaySub::JoinFail);
        assert_eq!(
            relay.fields.u8(fid::F_PROOF_RESULT).expect("result"),
            Some(PROOF_RESULT_PROOF_INVALID)
        );
    }

    #[test]
    fn u_join_proof_responder_ignores_other_relay_subs() {
        let cluster = cluster();
        let master =
            Arc::new(MasterKey::derive_from_password(b"responder-test", &cluster).expect("master"));
        let signing = Arc::new(SigningKey::from_seed(&cluster, [0x43; 32]));
        let ring = Arc::new(KeyRing::derive(&[7u8; 32], &cluster).expect("ring"));
        let keys = Arc::new(Mutex::new(KeyDirectory::new(cluster)));
        let responder = JoinProofResponder::new(master, signing, Arc::clone(&ring), keys, cluster);
        let mut writer = WcpWriter::new();
        writer.u8(fid::F_SUB_KIND, RelaySub::ManifestReq.as_u8());
        writer.bytes(fid::F_EXTRA, &1u64.to_le_bytes());
        let body = writer.finish().expect("body");
        let frame = seal_relay(
            ring.as_ref(),
            &NonceMinter::with_instance(2),
            SessionId::new(0x7003),
            &body,
        )
        .expect("frame");
        assert!(responder.answer(&frame).is_none());
    }
}
