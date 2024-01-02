use noise_protocol::patterns::{HandshakePattern, Token};
use noise_protocol::Cipher;
use quinn_proto::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};
use ring::aead;
use std::any::Any;
use std::convert::TryInto;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::noise_impl::{ChaCha20Poly1305, HandshakeState, Sensitive};
use crate::HandshakeData;

mod client;
mod server;

fn handshake_pattern() -> HandshakePattern {
    HandshakePattern::new(
        &[],
        &[Token::S],
        &[
            &[Token::E, Token::ES, Token::S, Token::SS],
            &[Token::E, Token::EE, Token::SE],
        ],
        "Noise_IK_25519_ChaChaPoly_BLAKE3",
    )
}

fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
    struct PlaintextHeaderKey;
    impl HeaderKey for PlaintextHeaderKey {
        fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn sample_size(&self) -> usize {
            0
        }
    }

    KeyPair {
        local: Box::new(PlaintextHeaderKey),
        remote: Box::new(PlaintextHeaderKey),
    }
}

fn initial_keys() -> Keys {
    Keys {
        header: header_keypair(),
        packet: KeyPair {
            local: Box::new(Sensitive(Zeroizing::new([0; 32]))),
            remote: Box::new(Sensitive(Zeroizing::new([0; 32]))),
        },
    }
}

trait State: 'static + Send + Sync {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }

    fn read_handshake(
        self: Box<Self>,
        _data: &mut CommonData,
        _handshake: &[u8],
    ) -> Result<Box<dyn State>, TransportError> {
        Err(TransportError {
            code: TransportErrorCode::CONNECTION_REFUSED,
            frame: None,
            reason: "unexpected crypto frame".to_string(),
        })
    }

    #[allow(clippy::type_complexity)]
    fn write_handshake(
        self: Box<Self>,
        data: &CommonData,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>);

    fn is_handshaking(&self) -> bool {
        true
    }

    fn get_channel_binding(&self) -> &[u8] {
        &[]
    }
}

fn client_server(state: &HandshakeState) -> (Sensitive<[u8; 32]>, Sensitive<[u8; 32]>) {
    let (client, server) = state.get_ciphers();
    let (client, 0) = client.extract() else {
        panic!("expected nonce to be 0")
    };
    let (server, 0) = server.extract() else {
        panic!("expected nonce to be 0")
    };
    (client, server)
}

struct Data {
    keys: KeyPair<Sensitive<[u8; 32]>>,
    hash: [u8; 32],
}

impl Data {
    fn next_keys(&mut self) -> KeyPair<Sensitive<[u8; 32]>> {
        let KeyPair { local, remote } = &mut self.keys;
        let next_local = ChaCha20Poly1305::rekey(local);
        let next_remote = ChaCha20Poly1305::rekey(remote);
        KeyPair {
            local: std::mem::replace(local, next_local),
            remote: std::mem::replace(remote, next_remote),
        }
    }
}

impl State for Data {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let keys = self.next_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        (self, None)
    }

    fn is_handshaking(&self) -> bool {
        false
    }

    fn get_channel_binding(&self) -> &[u8] {
        &self.hash
    }
}

struct NoiseSession {
    state: Result<Box<dyn State>, TransportError>,
    data: CommonData,
}

struct CommonData {
    requested_protocols: Vec<Vec<u8>>,
    supported_protocols: Vec<Vec<u8>>,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
    remote_s: Option<PublicKey>,
}

fn connection_refused(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame: None,
        reason: reason.to_string(),
    }
}

fn split(data: &[u8], n: usize) -> Result<(&[u8], &[u8]), TransportError> {
    if data.len() < n {
        Err(connection_refused("invalid crypto frame"))
    } else {
        Ok(data.split_at(n))
    }
}

fn split_n<const N: usize>(data: &[u8]) -> Result<(&[u8; N], &[u8]), TransportError> {
    let (n, data) = split(data, N)?;
    Ok((n.try_into().unwrap(), data))
}

fn noise_error(e: noise_protocol::Error) -> TransportError {
    match e.kind() {
        noise_protocol::ErrorKind::DH => {
            unreachable!("this diffie-hellman implementation cannot fail")
        }
        noise_protocol::ErrorKind::NeedPSK => {
            unreachable!("this noise implementation should not need PSK")
        }
        noise_protocol::ErrorKind::Decryption => {
            connection_refused("could not decrypt handshake message")
        }
        noise_protocol::ErrorKind::TooShort => connection_refused("handshake message is too short"),
    }
}

impl Session for NoiseSession {
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        initial_keys()
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.state.as_mut().unwrap().next_1rtt_keys()
    }

    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        self.state = Ok(std::mem::replace(
            &mut self.state,
            Err(connection_refused("broken poison state")),
        )?
        .read_handshake(&mut self.data, handshake)?);

        Ok(!self.data.requested_protocols.is_empty())
    }

    fn write_handshake(&mut self, handshake: &mut Vec<u8>) -> Option<Keys> {
        let (state, keys) = std::mem::replace(
            &mut self.state,
            Err(connection_refused("broken poison state")),
        )
        .unwrap()
        .write_handshake(&self.data, handshake);

        self.state = Ok(state);

        keys.map(|keys| Keys {
            header: header_keypair(),
            packet: KeyPair {
                local: Box::new(keys.local),
                remote: Box::new(keys.remote),
            },
        })
    }

    fn is_handshaking(&self) -> bool {
        self.state.as_ref().unwrap().is_handshaking()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.data.remote_s?))
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(Some(
            self.data
                .remote_transport_parameters
                .unwrap_or(self.data.transport_parameters),
        ))
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(HandshakeData {
            alpn: self.data.requested_protocols.get(0)?.clone(),
        }))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        blake3::Hasher::new_derive_key(
            "QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 export keying material",
        )
        .update(context)
        .update(self.state.as_ref().unwrap().get_channel_binding())
        .update(label)
        .finalize_xof()
        .fill(output);
        Ok(())
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(true)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];
