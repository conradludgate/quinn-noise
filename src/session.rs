use crate::aead::{header_keypair, Blake3, ChaCha20Poly1305, Sensitive, X25519};
use noise_protocol::patterns::{HandshakePattern, Token};
use noise_protocol::{Cipher, HandshakeState};
use quinn_proto::crypto::{
    ClientConfig, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, ServerConfig,
    Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use ring::aead;
use std::any::Any;
use std::convert::TryInto;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct NoiseClientConfig {
    /// Keypair to use.
    pub keypair: StaticSecret,
    /// The remote public key. This needs to be set.
    pub remote_public_key: PublicKey,
    /// Requested ALPN identifiers.
    pub requested_protocols: Vec<Vec<u8>>,
}

pub struct NoiseServerConfig {
    /// Keypair to use.
    pub keypair: StaticSecret,
    /// Supported ALPN identifiers.
    pub supported_protocols: Vec<Vec<u8>>,
}

impl ClientConfig for NoiseClientConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let pattern = HandshakePattern::new(
            &[],
            &[Token::S],
            &[
                &[Token::E, Token::ES, Token::S, Token::SS],
                &[Token::E, Token::EE, Token::SE],
            ],
            "Noise_IK_25519_ChaChaPoly_BLAKE3",
        );

        let handshake_state = HandshakeState::<X25519, ChaCha20Poly1305, Blake3>::new(
            pattern,
            true,
            [],
            Some(Sensitive(Zeroizing::new(self.keypair.to_bytes()))),
            None,
            Some(self.remote_public_key.to_bytes()),
            None,
        );

        Ok(Box::new(NoiseSession {
            state: Ok(Box::new(ClientInitial {
                state: handshake_state,
            })),
            data: Data {
                requested_protocols: self.requested_protocols.clone(),
                supported_protocols: vec![],
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: Some(self.remote_public_key),
            },
        }))
    }
}

pub(crate) fn initial_keys() -> Keys {
    Keys {
        header: header_keypair(),
        packet: KeyPair {
            local: Box::new(Sensitive(Zeroizing::new([0; 32]))),
            remote: Box::new(Sensitive(Zeroizing::new([0; 32]))),
        },
    }
}

impl ServerConfig for NoiseServerConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        let pattern = HandshakePattern::new(
            &[],
            &[Token::S],
            &[
                &[Token::E, Token::ES, Token::S, Token::SS],
                &[Token::E, Token::EE, Token::SE],
            ],
            "Noise_IK_25519_ChaChaPoly_BLAKE3",
        );

        let handshake_state = HandshakeState::<X25519, ChaCha20Poly1305, Blake3>::new(
            pattern,
            false,
            [],
            Some(Sensitive(Zeroizing::new(self.keypair.to_bytes()))),
            None,
            None,
            None,
        );

        Box::new(NoiseSession {
            state: Ok(Box::new(ServerInitial {
                state: handshake_state,
            })),
            data: Data {
                requested_protocols: vec![],
                supported_protocols: self.supported_protocols.clone(),
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: None,
            },
        })
    }

    fn initial_keys(
        &self,
        _version: u32,
        _dst_cid: &ConnectionId,
        _side: Side,
    ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
        Ok(initial_keys())
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

trait TState: 'static + Send + Sync {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }

    fn read_handshake(
        self: Box<Self>,
        _data: &mut Data,
        _handshake: &[u8],
    ) -> Result<Box<dyn TState>, TransportError> {
        Err(TransportError {
            code: TransportErrorCode::CONNECTION_REFUSED,
            frame: None,
            reason: "unexpected crypto frame".to_string(),
        })
    }

    #[allow(clippy::type_complexity)]
    fn write_handshake(
        self: Box<Self>,
        data: &Data,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>);

    fn is_handshaking(&self) -> bool {
        true
    }

    fn get_channel_binding(&self) -> &[u8] {
        &[]
    }
}

struct ServerInitial {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
}

struct ServerZeroRTT {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
    alpn: Option<Vec<u8>>,
}

struct ServerHandshake {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
    alpn: Option<Vec<u8>>,
}

impl TState for ServerInitial {
    fn read_handshake(
        mut self: Box<Self>,
        data: &mut Data,
        handshake: &[u8],
    ) -> Result<Box<dyn TState>, TransportError> {
        println!("read Initial server");
        let trailing = self
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;

        // alpn
        let (&[len], rest) = split_n(&trailing)?;
        let (mut alpns, mut transport_params) = split(rest, len as usize)?;

        let mut found_alpn = None;
        if !data.supported_protocols.is_empty() {
            while !alpns.is_empty() {
                let (&[len], next) = split_n(alpns)?;
                let (alpn, next_alpn) = split(next, len as usize)?;
                alpns = next_alpn;
                let found = data
                    .supported_protocols
                    .iter()
                    .any(|proto| proto.as_slice() == alpn);

                if found {
                    found_alpn = Some(alpn.to_vec());
                    break;
                }
            }
            if found_alpn.is_none() {
                return Err(connection_refused("unsupported alpn"));
            }
        }

        data.remote_transport_parameters = Some(TransportParameters::read(
            Side::Server,
            &mut transport_params,
        )?);

        Ok(Box::new(ServerZeroRTT {
            state: self.state,
            alpn: found_alpn,
        }))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write Initial server");
        (self, None)
    }
}

fn client_server(
    state: &HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
) -> (Sensitive<[u8; 32]>, Sensitive<[u8; 32]>) {
    let (client, server) = state.get_ciphers();
    let (client, 0) = client.extract() else {
        panic!("expected nonce to be 0")
    };
    let (server, 0) = server.extract() else {
        panic!("expected nonce to be 0")
    };
    (client, server)
}
fn server_keys(
    state: &HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
) -> KeyPair<Sensitive<[u8; 32]>> {
    let (client, server) = client_server(state);
    KeyPair {
        local: server,
        remote: client,
    }
}

impl TState for ServerZeroRTT {
    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write ZeroRTT server");
        let keys = server_keys(&self.state);
        (
            Box::new(ServerHandshake {
                state: self.state,
                alpn: self.alpn,
            }),
            Some(keys),
        )
    }
}

impl TState for ServerHandshake {
    fn write_handshake(
        mut self: Box<Self>,
        data: &Data,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write Handshake server");
        // payload
        let mut payload = vec![];

        // alpn
        if let [alpn] = &*data.requested_protocols {
            payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
            payload.extend_from_slice(alpn);
        }

        data.transport_parameters.write(&mut payload);

        let overhead = self.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);
        self.state.write_message(&payload, handshake).unwrap();

        let mut data = DataState {
            hash: self.state.get_hash().try_into().unwrap(),
            keys: server_keys(&self.state),
            alpn: self.alpn,
        };

        let keys = data.next_keys();
        (Box::new(data), Some(keys))
    }
}

struct ClientInitial {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
}

struct ClientZeroRTT {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
}

struct ClientHandshake {
    state: HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
}

struct ClientOneRTT {
    keys: KeyPair<Sensitive<[u8; 32]>>,
    hash: [u8; 32],
    alpn: Option<Vec<u8>>,
}

impl TState for ClientInitial {
    fn write_handshake(
        mut self: Box<Self>,
        data: &Data,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write Initial client");

        // payload
        let mut payload = vec![];

        // alpn
        let len = data
            .requested_protocols
            .iter()
            .map(|s| s.len() as u8 + 1)
            .sum::<u8>();
        payload.extend_from_slice(&len.to_le_bytes());
        for alpn in &data.requested_protocols {
            payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
            payload.extend_from_slice(alpn);
        }

        data.transport_parameters.write(&mut payload);

        let overhead = self.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);
        self.state.write_message(&payload, handshake).unwrap();

        (Box::new(ClientZeroRTT { state: self.state }), None)
    }
}

fn client_keys(
    state: &HandshakeState<X25519, ChaCha20Poly1305, Blake3>,
) -> KeyPair<Sensitive<[u8; 32]>> {
    let (client, server) = client_server(state);
    KeyPair {
        local: client,
        remote: server,
    }
}

impl TState for ClientZeroRTT {
    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write ZeroRTT client");
        let keys = client_keys(&self.state);
        (Box::new(ClientHandshake { state: self.state }), Some(keys))
    }
}

impl TState for ClientHandshake {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }

    fn read_handshake(
        mut self: Box<Self>,
        data: &mut Data,
        handshake: &[u8],
    ) -> Result<Box<dyn TState>, TransportError> {
        println!("read Handshake client");
        let trailing = self
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;

        // alpn
        let (&[len], rest) = split_n(&trailing)?;
        let (alpn, mut transport_params) = split(rest, len as usize)?;
        let mut found_alpn = None;
        if !data.requested_protocols.is_empty() {
            if alpn.is_empty() {
                return Err(connection_refused("unsupported alpn"));
            }
            found_alpn = Some(alpn.to_vec());
        }

        data.remote_transport_parameters = Some(TransportParameters::read(
            Side::Client,
            &mut transport_params,
        )?);

        Ok(Box::new(ClientOneRTT {
            hash: self.state.get_hash().try_into().unwrap(),
            keys: client_keys(&self.state),
            alpn: found_alpn,
        }))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write Handshake client");
        (self, None)
    }
}

impl TState for ClientOneRTT {
    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write OneRTT client");
        let mut data = DataState {
            hash: self.hash,
            keys: self.keys,
            alpn: self.alpn,
        };

        let keys = data.next_keys();
        (Box::new(data), Some(keys))
    }

    fn is_handshaking(&self) -> bool {
        false
    }

    fn get_channel_binding(&self) -> &[u8] {
        &self.hash
    }
}

struct DataState {
    keys: KeyPair<Sensitive<[u8; 32]>>,
    hash: [u8; 32],
    alpn: Option<Vec<u8>>,
}

impl DataState {
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

impl TState for DataState {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let keys = self.next_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &Data,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn TState>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        println!("write Data");
        (self, None)
    }

    fn is_handshaking(&self) -> bool {
        false
    }

    fn get_channel_binding(&self) -> &[u8] {
        &self.hash
    }
}

pub struct NoiseSession {
    state: Result<Box<dyn TState>, TransportError>,
    data: Data,
}

struct Data {
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
        Some(Box::new(self.data.requested_protocols.get(0)?.clone()))
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
