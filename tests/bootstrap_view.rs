//! Empty-cluster bootstrap view acceptance.
//!
//! cargo test --locked --features testkit --test bootstrap_view -- --nocapture

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use syncmount::protocol::{
    decode_plain, encode_frame, ClientId, CtrlPrefix, Flags, FrameBuf, FrameDecoder, FrameHeader,
    FrameRef, Limits, Message, MsgType, Prefix, Seq,
};
use syncmount::server::{ServeConfig, Server};
use syncmount::transport::{DialOptions, Endpoint, HttpTransport};
use tokio::sync::oneshot;

struct Harness {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    async fn boot() -> Self {
        let server = Server::bind(ServeConfig::for_tests()).await.expect("bind");
        let addr = server.local_addr().expect("addr");
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(server.run_with_shutdown(async {
            let _ = stop_rx.await;
        }));
        Self { addr, stop, task }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }
}

fn control_frame(msg_type: MsgType, prefix: Prefix, body: Vec<u8>, seq: Seq) -> Vec<u8> {
    let mut flags = Flags::EMPTY;
    match prefix.kind() {
        syncmount::protocol::PrefixKind::None => {}
        syncmount::protocol::PrefixKind::Route => flags = flags.with(Flags::ROUTED),
        syncmount::protocol::PrefixKind::Ctrl => flags = flags.with(Flags::CTRL),
    }
    let mut header = FrameHeader::new(msg_type, flags, 0, seq);
    header.len = u32::try_from(prefix.encoded_len() + body.len()).unwrap();
    encode_frame(&FrameRef::new(&header, &prefix, &body)).unwrap()
}

fn decode_frame(bytes: &[u8]) -> FrameBuf {
    let mut decoder = FrameDecoder::new(Limits::default());
    decoder.push(bytes).unwrap();
    decoder.next_frame_owned().unwrap().unwrap()
}

async fn recv(transport: &mut HttpTransport) -> Option<FrameBuf> {
    let bytes = tokio::time::timeout(Duration::from_secs(2), transport.recv())
        .await
        .ok()?
        .ok()??;
    Some(decode_frame(&bytes))
}

/// Send one plaintext `HELLO` and return the `WELCOME`.
async fn hello(addr: SocketAddr, id: ClientId) -> (HttpTransport, syncmount::protocol::Welcome) {
    let endpoint = Endpoint::parse(&format!("http://{addr}/")).expect("endpoint");
    let mut transport = HttpTransport::dial(&endpoint, &DialOptions::random())
        .await
        .expect("dial");
    let hello = syncmount::protocol::Hello::new(
        syncmount::protocol::ProtoVersion::CURRENT,
        syncmount::protocol::Caps::REQUIRED.union(syncmount::protocol::Caps::VIEW_SOURCE),
        id,
        [7u8; 32],
    );
    let body = hello.encode().expect("hello body");
    let frame = control_frame(
        MsgType::HELLO,
        Prefix::Ctrl(CtrlPrefix::new(Seq::UNSEQUENCED, 0)),
        body,
        Seq::UNSEQUENCED,
    );
    transport.send(Bytes::from(frame)).await.expect("send");
    let frame = recv(&mut transport).await.expect("WELCOME");
    assert_eq!(frame.header.msg_type, MsgType::WELCOME);
    match decode_plain(frame.header.msg_type, &frame.body, &Limits::default()).expect("decode") {
        Message::Welcome(welcome) => (transport, welcome),
        other => panic!("expected WELCOME, got {other:?}"),
    }
}

/// The first identity on an empty cluster is told to use its disk as the
/// sequence-zero view. A second identity that arrives while the first is
/// still attached is not a bootstrap source.
#[tokio::test]
async fn bv_only_the_first_identity_gets_a_bootstrap_view() {
    let harness = Harness::boot().await;

    let (_first, first) = hello(harness.addr, ClientId::from_bytes([0xb1; 16])).await;
    assert_eq!(first.current_seq, Seq::UNSEQUENCED);
    assert!(first.view_bootstrap);
    assert!(!first.view_self);
    assert_eq!(first.view_holder, None);
    assert_eq!(first.view_seq, None);
    assert_eq!(first.view_session, None);

    // The first transport stays alive: the server sees another attached
    // identity even before its downlink is paired.
    let (_second, second) = hello(harness.addr, ClientId::from_bytes([0xb2; 16])).await;
    assert!(!second.view_bootstrap);
    assert!(!second.view_self);
    match (second.view_holder, second.view_seq, second.view_session) {
        // The first client has not paired its downlink yet: no holder.
        (None, None, None) => {}
        // Or it is already online and serves the zero view.
        (Some(holder), Some(seq), Some(session)) => {
            assert_eq!(holder, ClientId::from_bytes([0xb1; 16]));
            assert_eq!(seq, Seq::UNSEQUENCED);
            assert_ne!(session, syncmount::protocol::SessionId::ZERO);
        }
        other => panic!("partial view source: {other:?}"),
    }

    harness.shutdown().await;
}
