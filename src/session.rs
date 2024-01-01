use crate::aead::{header_keypair, ChaCha20PacketKey, PlaintextHeaderKey};
use crate::dh::DiffieHellman;
use crate::keylog::KeyLog;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn_proto::crypto::{
    ClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
    ServerConfig, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use ring::aead;
use std::any::Any;
use std::convert::TryInto;
use std::sync::Arc;

pub struct NoiseClientConfig {
    /// Keypair to use.
    pub keypair: SigningKey,
    /// Optional private shared key usable as a password for private networks.
    pub psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    pub keylogger: Option<Arc<dyn KeyLog>>,
    /// The remote public key. This needs to be set.
    pub remote_public_key: VerifyingKey,
    /// Requested ALPN identifiers.
    pub requested_protocols: Vec<Vec<u8>>,
}

impl From<NoiseClientConfig> for NoiseConfig {
    fn from(config: NoiseClientConfig) -> Self {
        Self {
            keypair: Some(config.keypair),
            psk: config.psk,
            keylogger: config.keylogger,
            remote_public_key: Some(config.remote_public_key),
            requested_protocols: config.requested_protocols,
            supported_protocols: vec![],
        }
    }
}

pub struct NoiseServerConfig {
    /// Keypair to use.
    pub keypair: SigningKey,
    /// Optional private shared key usable as a password for private networks.
    pub psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    pub keylogger: Option<Arc<dyn KeyLog>>,
    /// Supported ALPN identifiers.
    pub supported_protocols: Vec<Vec<u8>>,
}

impl From<NoiseServerConfig> for NoiseConfig {
    fn from(config: NoiseServerConfig) -> Self {
        Self {
            keypair: Some(config.keypair),
            psk: config.psk,
            keylogger: config.keylogger,
            remote_public_key: None,
            requested_protocols: vec![],
            supported_protocols: config.supported_protocols,
        }
    }
}

/// Noise configuration struct.
#[derive(Default)]
pub struct NoiseConfig {
    /// Keypair to use.
    keypair: Option<SigningKey>,
    /// Optional private shared key usable as a password for private networks.
    psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    keylogger: Option<Arc<dyn KeyLog>>,
    /// The remote public key. This needs to be set.
    remote_public_key: Option<VerifyingKey>,
    /// Requested ALPN identifiers.
    requested_protocols: Vec<Vec<u8>>,
    /// Supported ALPN identifiers.
    supported_protocols: Vec<Vec<u8>>,
}

impl ClientConfig for NoiseConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        Ok(Box::new(NoiseConfig::start_session(
            &self,
            Side::Client,
            params,
        )))
    }
}

impl ServerConfig for NoiseConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(NoiseConfig::start_session(&self, Side::Server, params))
    }

    fn initial_keys(
        &self,
        _version: u32,
        _dst_cid: &ConnectionId,
        _side: Side,
    ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
        Ok(Keys {
            header: header_keypair(),
            packet: KeyPair {
                local: Box::new(ChaCha20PacketKey::new([0; 32])),
                remote: Box::new(ChaCha20PacketKey::new([0; 32])),
            },
        })
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

impl NoiseConfig {
    fn start_session(&self, side: Side, params: &TransportParameters) -> NoiseSession {
        let mut rng = rand_core::OsRng {};
        let s = if let Some(keypair) = self.keypair.as_ref() {
            SigningKey::from_bytes(keypair.as_bytes())
        } else {
            SigningKey::generate(&mut rng)
        };
        let e = SigningKey::generate(&mut rng);

        let mut symmetricstate = SymmetricState::initialize_symmetric(PROTOCOL_ID.as_bytes());

        // <- s
        match side {
            Side::Server => symmetricstate.mix_hash(s.verifying_key().as_bytes()),
            Side::Client => symmetricstate.mix_hash(self.remote_public_key.unwrap().as_bytes()),
        }

        NoiseSession {
            symmetricstate,
            next_keys: None,
            state: State::Initial,
            side,
            e,
            s,
            requested_protocols: self.requested_protocols.clone(),
            supported_protocols: self.supported_protocols.clone(),
            transport_parameters: *params,
            remote_transport_parameters: None,
            remote_e: None,
            remote_s: self.remote_public_key,
            zero_rtt_key: None,
        }
    }
}

impl Clone for NoiseConfig {
    fn clone(&self) -> Self {
        let keypair = self
            .keypair
            .as_ref()
            .map(|keypair| SigningKey::from_bytes(keypair.as_bytes()));
        Self {
            keypair,
            psk: self.psk,
            keylogger: self.keylogger.clone(),
            remote_public_key: self.remote_public_key,
            requested_protocols: self.requested_protocols.clone(),
            supported_protocols: self.supported_protocols.clone(),
        }
    }
}

const PROTOCOL_ID: &str = "Noise_IK_25519_ChaChaPoly_BLAKE3";

#[derive(Copy, Clone, Default)]
pub(crate) struct SymmetricStateData {}

pub(crate) struct SymmetricState {
    cipherstate: Option<ChaCha20PacketKey>,
    h: [u8; 32],
    ck: [u8; 32],
}

impl SymmetricState {
    pub fn initialize_symmetric(protocol_id: &[u8]) -> Self {
        let h = blake3::hash(protocol_id).into();
        Self {
            h,
            ck: h,
            cipherstate: None,
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        // Sets ck, temp_k = HKDF(ck, input_key_material, 2).
        // If HASHLEN is 64, then truncates temp_k to 32 bytes.
        // Calls InitializeKey(temp_k).
        let mut bytes = blake3::Hasher::new_derive_key(PROTOCOL_ID)
            .update(&self.ck)
            .update(input_key_material)
            .finalize_xof();
        bytes.fill(&mut self.ck);
        let mut cipher = [0; 32];
        bytes.fill(&mut cipher);
        self.cipherstate = Some(ChaCha20PacketKey::new(cipher));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = blake3::Hasher::new()
            .update(&self.h)
            .update(data)
            .finalize()
            .into();
    }

    // pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
    //     // Sets ck, temp_h, temp_k = HKDF(ck, input_key_material, 3).
    //     // Calls MixHash(temp_h).
    //     // If HASHLEN is 64, then truncates temp_k to 32 bytes.
    //     // Calls InitializeKey(temp_k).
    //     let mut bytes = blake3::Hasher::new_derive_key(PROTOCOL_ID)
    //         .update(&self.ck)
    //         .update(input_key_material)
    //         .finalize_xof();

    //     let mut mix = [0; 32];
    //     let mut cipher = [0; 32];
    //     bytes.fill(&mut self.ck);
    //     bytes.fill(&mut mix);
    //     bytes.fill(&mut cipher);

    //     self.mix_hash(&mix);
    //     self.cipherstate = Some(ChaCha20PacketKey::new(cipher));
    // }

    /// Encrypt a message and mixes in the hash of the output
    pub fn encrypt_and_hash(&mut self, nonce: u64, plaintext: &[u8], buffer: &mut [u8]) -> usize {
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        let output_len = if let Some(cipher) = &self.cipherstate {
            cipher.encrypt_ad(nonce, &self.h, &mut buffer[..plaintext.len() + 16]);
            plaintext.len() + 16
        } else {
            plaintext.len()
        };
        self.mix_hash(&buffer[..output_len]);
        output_len
    }

    pub fn decrypt_and_hash(
        &mut self,
        nonce: u64,
        ciphertext: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let payload_len = if let Some(cipher) = &self.cipherstate {
            let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
            buffer[..ciphertext.len()].copy_from_slice(ciphertext);
            cipher.decrypt_ad(nonce, &self.h, tag, &mut buffer[..ciphertext.len()])?;
            ciphertext.len()
        } else {
            buffer[..ciphertext.len()].copy_from_slice(ciphertext);
            ciphertext.len()
        };
        self.mix_hash(ciphertext);
        Ok(payload_len)
    }

    pub fn split(&mut self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = blake3::Hasher::new_derive_key(PROTOCOL_ID)
            .update(&self.ck)
            .finalize_xof();

        let mut temp_k1 = [0; 32];
        let mut temp_k2 = [0; 32];
        bytes.fill(&mut temp_k1);
        bytes.fill(&mut temp_k2);

        (temp_k1, temp_k2)
    }
}

pub struct NoiseSession {
    symmetricstate: SymmetricState,
    next_keys: Option<KeyPair<[u8; 32]>>,
    state: State,
    side: Side,
    e: SigningKey,
    s: SigningKey,
    requested_protocols: Vec<Vec<u8>>,
    supported_protocols: Vec<Vec<u8>>,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
    remote_e: Option<VerifyingKey>,
    remote_s: Option<VerifyingKey>,
    zero_rtt_key: Option<ChaCha20PacketKey>,
}

// impl NoiseSession {
//     fn conn_id(&self) -> Option<[u8; 32]> {
//         match self.side {
//             Side::Client => Some(self.e.verifying_key().to_bytes()),
//             Side::Server => Some(self.remote_e.as_ref()?.to_bytes()),
//         }
//     }
// }

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
    Data,
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

impl Session for NoiseSession {
    fn initial_keys(&self, _: &ConnectionId, _: Side) -> Keys {
        Keys {
            header: header_keypair(),
            packet: KeyPair {
                local: Box::new(ChaCha20PacketKey::new([0; 32])),
                remote: Box::new(ChaCha20PacketKey::new([0; 32])),
            },
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let KeyPair { local, remote } = *self.next_keys.as_ref()?;
        self.next_keys = Some(KeyPair {
            local: blake3::derive_key("update key", &local),
            remote: blake3::derive_key("update key", &remote),
        });

        Some(KeyPair {
            local: Box::new(ChaCha20PacketKey::new(local)),
            remote: Box::new(ChaCha20PacketKey::new(remote)),
        })
    }

    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        tracing::trace!("read_handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (State::Initial, Side::Server) => {
                // -> e
                let (re, rest) = split_n(handshake)?;
                self.symmetricstate.mix_hash(re);
                let re = VerifyingKey::from_bytes(re)
                    .map_err(|_| connection_refused("invalid ephemeral public key"))?;
                self.remote_e = Some(re);

                // -> es
                let es = self.s.diffie_hellman(&re);
                self.symmetricstate.mix_key(&es);

                // -> s
                let (remote_s, rest) = split_n::<48>(rest)?;
                let mut rs = [0; 32];
                self.symmetricstate
                    .decrypt_and_hash(0, remote_s, &mut rs)
                    .map_err(|_| connection_refused("invalid static public key1"))?;
                let rs = VerifyingKey::from_bytes(&rs)
                    .map_err(|_| connection_refused("invalid static public key2"))?;
                self.remote_s = Some(rs);

                // -> ss
                let ss = self.s.diffie_hellman(&rs);
                self.symmetricstate.mix_key(&ss);

                // payload
                let mut payload = vec![0; rest.len() - 16];
                self.symmetricstate
                    .decrypt_and_hash(0, rest, &mut payload)
                    .map_err(|_| connection_refused("invalid static public key3"))?;

                // alpn
                let (&[len], rest) = split_n(&payload)?;
                let (mut alpns, mut transport_params) = split(rest, len as usize)?;

                if !self.supported_protocols.is_empty() {
                    let mut is_supported = false;
                    while !alpns.is_empty() {
                        let (&[len], next) = split_n(alpns)?;
                        let (alpn, next_alpn) = split(next, len as usize)?;
                        alpns = next_alpn;
                        let found = self
                            .supported_protocols
                            .iter()
                            .any(|proto| proto.as_slice() == alpn);

                        if found {
                            self.requested_protocols.push(alpn.to_vec());
                            is_supported = true;
                            break;
                        }
                    }
                    if !is_supported {
                        return Err(connection_refused("unsupported alpn"));
                    }
                }

                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Server,
                    &mut transport_params,
                )?);
                self.state = State::ZeroRtt;
                Ok(!self.requested_protocols.is_empty())
            }
            (State::Handshake, Side::Client) => {
                // <- e
                let (re, rest) = split_n::<32>(handshake)?;
                self.symmetricstate.mix_hash(re);
                let re = VerifyingKey::from_bytes(re)
                    .map_err(|_| connection_refused("invalid ephemeral public key"))?;
                self.remote_e = Some(re);

                // <- ee
                let ee = self.e.diffie_hellman(&re);
                self.symmetricstate.mix_key(&ee);

                // <- se
                let se = self.s.diffie_hellman(&re);
                self.symmetricstate.mix_key(&se);

                // payload
                let mut payload = vec![0; rest.len() - 16];
                self.symmetricstate
                    .decrypt_and_hash(0, rest, &mut payload)
                    .map_err(|_| connection_refused("invalid payload"))?;

                // alpn
                let (&[len], rest) = split_n(&payload)?;
                let (alpn, mut transport_params) = split(rest, len as usize)?;
                if !self.requested_protocols.is_empty() {
                    if alpn.is_empty() {
                        return Err(connection_refused("unsupported alpn"));
                    }
                    self.requested_protocols.retain(|a| a == alpn);
                    self.requested_protocols.truncate(1);
                }

                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Client,
                    &mut transport_params,
                )?);
                self.state = State::OneRtt;
                Ok(!self.requested_protocols.is_empty())
            }
            _ => Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected crypto frame".to_string(),
            }),
        }
    }

    fn write_handshake(&mut self, handshake: &mut Vec<u8>) -> Option<Keys> {
        tracing::trace!("write_handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (State::Initial, Side::Client) => {
                // -> e
                self.symmetricstate
                    .mix_hash(self.e.verifying_key().as_bytes());
                handshake.extend_from_slice(self.e.verifying_key().as_bytes());

                // -> es
                let es = self.e.diffie_hellman(&self.remote_s.unwrap());
                self.symmetricstate.mix_key(&es);

                // -> s
                let mut s = [0; 48];
                self.symmetricstate
                    .encrypt_and_hash(0, self.s.verifying_key().as_bytes(), &mut s);
                handshake.extend_from_slice(&s);

                // -> ss
                let s = self.remote_s.unwrap();
                let ss = self.s.diffie_hellman(&s);
                self.symmetricstate.mix_key(&ss);

                // payload
                let mut payload = vec![];

                // alpn
                let len = self
                    .requested_protocols
                    .iter()
                    .map(|s| s.len() as u8 + 1)
                    .sum::<u8>();
                payload.extend_from_slice(&len.to_le_bytes());
                for alpn in &self.requested_protocols {
                    payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
                    payload.extend_from_slice(alpn);
                }

                self.transport_parameters.write(&mut payload);

                let i = handshake.len();
                handshake.resize(i + 16 + payload.len(), 0);
                self.symmetricstate
                    .encrypt_and_hash(0, &payload, &mut handshake[i..]);

                // 0-rtt
                self.state = State::ZeroRtt;
                None
            }
            (State::ZeroRtt, _) => {
                let (client, server) = self.symmetricstate.split();
                let kp = match self.side {
                    Side::Client => KeyPair {
                        local: client,
                        remote: server,
                    },
                    Side::Server => KeyPair {
                        local: server,
                        remote: client,
                    },
                };
                self.next_keys = Some(kp);
                self.state = State::Handshake;
                Some(Keys {
                    header: header_keypair(),
                    packet: self.next_1rtt_keys().unwrap(),
                })
            }
            (State::Handshake, Side::Server) => {
                // <- e
                self.symmetricstate
                    .mix_hash(self.e.verifying_key().as_bytes());
                handshake.extend_from_slice(self.e.verifying_key().as_bytes());

                // <- ee
                let ee = self.e.diffie_hellman(&self.remote_e.unwrap());
                self.symmetricstate.mix_key(&ee);

                // <- se
                let se = self.e.diffie_hellman(&self.remote_s.unwrap());
                self.symmetricstate.mix_key(&se);

                // payload
                let mut payload = vec![];

                // alpn
                if let [alpn] = &*self.requested_protocols {
                    payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
                    payload.extend_from_slice(alpn);
                }

                self.transport_parameters.write(&mut payload);

                let i = handshake.len();
                handshake.resize(i + 16 + payload.len(), 0);
                self.symmetricstate
                    .encrypt_and_hash(0, &payload, &mut handshake[i..]);

                // 1-rtt keys
                let (client, server) = self.symmetricstate.split();
                let kp = match self.side {
                    Side::Client => KeyPair {
                        local: client,
                        remote: server,
                    },
                    Side::Server => KeyPair {
                        local: server,
                        remote: client,
                    },
                };
                self.next_keys = Some(kp);
                let packet = self.next_1rtt_keys().unwrap();
                self.state = State::Data;
                Some(Keys {
                    header: header_keypair(),
                    packet,
                })
            }
            (State::OneRtt, _) => {
                let (client, server) = self.symmetricstate.split();
                let kp = match self.side {
                    Side::Client => KeyPair {
                        local: client,
                        remote: server,
                    },
                    Side::Server => KeyPair {
                        local: server,
                        remote: client,
                    },
                };
                self.next_keys = Some(kp);
                let packet = self.next_1rtt_keys().unwrap();
                self.state = State::Data;
                Some(Keys {
                    header: header_keypair(),
                    packet,
                })
            }
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.state != State::Data
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.remote_s?))
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        if self.state == State::Handshake && self.side == Side::Client {
            Ok(Some(self.transport_parameters))
        } else {
            Ok(self.remote_transport_parameters)
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.requested_protocols.get(0)?.clone()))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        blake3::Hasher::new_derive_key("export keying material")
            .update(context)
            .update(&self.symmetricstate.ck)
            .update(label)
            .finalize_xof()
            .fill(output);
        Ok(())
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        Some((
            Box::new(PlaintextHeaderKey),
            Box::new(self.zero_rtt_key.clone()?),
        ))
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
