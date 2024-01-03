use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};
use std::any::Any;
use std::convert::TryInto;
use subtle::ConstantTimeEq;

use crate::HandshakeData;

use self::packet_key::PacketKeyWrapper;

mod client;
mod packet_key;
mod server;

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

fn packet_keys<C: Cipher + 'static>(keys: KeyPair<C::Key>) -> KeyPair<Box<dyn PacketKey>>
where
    C::Key: 'static + Send,
{
    KeyPair {
        local: Box::new(PacketKeyWrapper::<C>(keys.local)),
        remote: Box::new(PacketKeyWrapper::<C>(keys.remote)),
    }
}

fn initial_keys<D: DH, C: Cipher + 'static, H: Hash>(state: &HandshakeState<D, C, H>) -> Keys
where
    C::Key: 'static + Send,
{
    Keys {
        header: header_keypair(),
        packet: packet_keys::<C>(keys(state)),
    }
}

fn client_server<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> (C::Key, C::Key) {
    let (client, server) = state.get_ciphers();
    let (client, 0) = client.extract() else {
        panic!("expected nonce to be 0")
    };
    let (server, 0) = server.extract() else {
        panic!("expected nonce to be 0")
    };
    (client, server)
}

struct InnerHandshakeState<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    // a little bit annoying that neither snow nor noise-protocol expose this field directly
    pattern: usize,
    needs_keys: bool,
}

fn keys<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> KeyPair<<C as Cipher>::Key> {
    let (client, server) = client_server(state);
    if state.get_is_initiator() {
        KeyPair {
            local: client,
            remote: server,
        }
    } else {
        KeyPair {
            local: server,
            remote: client,
        }
    }
}

impl<D: DH, C: Cipher, H: Hash> InnerHandshakeState<D, C, H> {
    fn connection_parameters_request(&self) -> bool {
        self.pattern + 3 >= self.state.get_pattern().get_message_patterns_len()
    }
    fn connection_parameters_response(&self) -> bool {
        self.pattern + 2 >= self.state.get_pattern().get_message_patterns_len()
    }
    fn keys(&self) -> KeyPair<<C as Cipher>::Key> {
        keys(&self.state)
    }
}

struct Data<C: Cipher, H: Hash> {
    keys: KeyPair<C::Key>,
    hash: H::Output,
}

impl<C: Cipher, H: Hash> Data<C, H> {
    fn next_keys(&mut self) -> KeyPair<C::Key> {
        let KeyPair { local, remote } = &mut self.keys;
        let next_local = C::rekey(local);
        let next_remote = C::rekey(remote);
        KeyPair {
            local: std::mem::replace(local, next_local),
            remote: std::mem::replace(remote, next_remote),
        }
    }
}

enum State<D: DH, C: Cipher, H: Hash> {
    Handshaking(Box<InnerHandshakeState<D, C, H>>),
    Complete(Data<C, H>),
}

struct NoiseSession<D: DH, C: Cipher, H: Hash> {
    state: State<D, C, H>,
    data: CommonData<D>,
    integrity_key: H::Output,
}

struct CommonData<D: DH> {
    negotiated_protocol: Option<Vec<u8>>,
    supported_protocols: Vec<Vec<u8>>,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
    remote_s: Option<D::Pubkey>,
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

pub fn get_integrity_key<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> H::Output {
    // same seed as QUIC-TLS <https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity>
    // > The secret key and the nonce are values derived by calling HKDF-Expand-Label using
    // > 0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e as the secret,
    // > with labels being "quic key" and "quic iv" (Section 5.1).
    //
    // In this case, I am using ("QUIC integrity key" || noise handshake pattern) as the label
    const SEED: [u8; 32] = [
        0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02, 0x81,
        0x4c, 0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f,
        0xca, 0x8e,
    ];
    let label = state.get_pattern().get_name();
    // hkdf_expand(SEED, label, output_size);
    H::hmac_many(&SEED, &[b"QUIC integrity key", label.as_bytes(), &[1u8]])
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> Session for NoiseSession<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        match &self.state {
            State::Handshaking(inner) => initial_keys(&inner.state),
            State::Complete(_) => unreachable!(),
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        match &mut self.state {
            State::Handshaking(_) => None,
            State::Complete(data) => Some(packet_keys::<C>(data.next_keys())),
        }
    }

    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        let State::Handshaking(inner) = &mut self.state else {
            return Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected crypto frame".to_string(),
            });
        };

        if inner.state.is_write_turn() {
            return Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected crypto frame".to_string(),
            });
        }

        let payload = inner
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;
        inner.pattern += 1;
        inner.needs_keys = true;

        self.data.remote_s = inner.state.get_rs();

        if !inner.state.get_is_initiator() && inner.connection_parameters_request() {
            // alpn
            let (&[len], rest) = split_n(&payload)?;
            let (mut alpns, mut transport_params) = split(rest, len as usize)?;

            if !self.data.supported_protocols.is_empty() {
                while !alpns.is_empty() {
                    let (&[len], next) = split_n(alpns)?;
                    let (alpn, next_alpn) = split(next, len as usize)?;
                    alpns = next_alpn;
                    let found = self
                        .data
                        .supported_protocols
                        .iter()
                        .any(|proto| proto.as_slice() == alpn);

                    if found {
                        self.data.negotiated_protocol = Some(alpn.to_vec());
                        break;
                    }
                }
                if self.data.negotiated_protocol.is_none() {
                    return Err(connection_refused("unsupported alpn"));
                }
            }

            self.data.remote_transport_parameters = Some(TransportParameters::read(
                Side::Server,
                &mut transport_params,
            )?);
        }

        if inner.state.get_is_initiator() && inner.connection_parameters_response() {
            // alpn
            let (&[len], rest) = split_n(&payload)?;
            let (alpn, mut transport_params) = split(rest, len as usize)?;
            self.data.negotiated_protocol =
                self.data.supported_protocols.drain(..).find(|p| p == alpn);
            if !self.data.supported_protocols.is_empty() && self.data.negotiated_protocol.is_none()
            {
                return Err(connection_refused("unsupported alpn"));
            }

            self.data.remote_transport_parameters = Some(TransportParameters::read(
                Side::Client,
                &mut transport_params,
            )?);
        }

        Ok(self.data.negotiated_protocol.is_some())
    }

    fn write_handshake(&mut self, handshake: &mut Vec<u8>) -> Option<Keys> {
        let State::Handshaking(inner) = &mut self.state else {
            return None;
        };

        let mut keys = inner.keys();
        if inner.state.completed() {
            let mut data = Data {
                keys,
                hash: H::Output::from_slice(inner.state.get_hash()),
            };
            keys = data.next_keys();
            self.state = State::Complete(data);

            return Some(Keys {
                header: header_keypair(),
                packet: packet_keys::<C>(keys),
            });
        }

        if inner.needs_keys {
            inner.needs_keys = false;

            return Some(Keys {
                header: header_keypair(),
                packet: packet_keys::<C>(keys),
            });
        }

        if !inner.state.is_write_turn() {
            return None;
        }

        // payload
        let mut payload = vec![];

        if inner.state.get_is_initiator() && inner.connection_parameters_request() {
            // alpn
            let len = self
                .data
                .supported_protocols
                .iter()
                .map(|s| s.len() as u8 + 1)
                .sum::<u8>();
            payload.extend_from_slice(&len.to_le_bytes());
            for alpn in &self.data.supported_protocols {
                payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
                payload.extend_from_slice(alpn);
            }

            self.data.transport_parameters.write(&mut payload);
        }

        if !inner.state.get_is_initiator() && inner.connection_parameters_response() {
            // alpn
            if let Some(alpn) = &self.data.negotiated_protocol {
                payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
                payload.extend_from_slice(alpn);
            }

            self.data.transport_parameters.write(&mut payload);
        }

        let overhead = inner.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);

        inner.state.write_message(&payload, handshake).unwrap();
        inner.pattern += 1;

        let mut keys = inner.keys();
        if inner.state.completed() {
            let mut data = Data {
                keys,
                hash: H::Output::from_slice(inner.state.get_hash()),
            };
            keys = data.next_keys();
            self.state = State::Complete(data);
        }

        Some(Keys {
            header: header_keypair(),
            packet: packet_keys::<C>(keys),
        })
    }

    fn is_handshaking(&self) -> bool {
        matches!(&self.state, State::Handshaking(_))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.data.remote_s.as_ref()?.clone()))
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
            alpn: self.data.negotiated_protocol.clone()?,
        }))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        if output.is_empty() {
            return Ok(());
        }
        if output.len() > H::hash_len() * 255 {
            return Err(ExportKeyingMaterialError);
        }

        let hash = match &self.state {
            State::Handshaking(_) => return Err(ExportKeyingMaterialError),
            State::Complete(data) => data.hash.as_slice(),
        };

        let mut chunks = output.chunks_mut(H::hash_len()).enumerate();
        let (i, chunk) = chunks.next().unwrap();
        let mut out = H::hmac_many(hash, &[label, context, &[(i + 1) as u8]]);
        chunk.copy_from_slice(&out.as_slice()[..chunk.len()]);

        for (i, chunk) in chunks {
            out = H::hmac_many(hash, &[label, context, out.as_slice(), &[(i + 1) as u8]]);
            chunk.copy_from_slice(&out.as_slice()[..chunk.len()]);
        }

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
        let (packet, tag) = payload.split_at(tag_start);

        let check = H::hmac_many(
            self.integrity_key.as_slice(),
            &[&[orig_dst_cid.len() as u8], orig_dst_cid, header, packet],
        );

        tag.ct_eq(&check.as_slice()[..16]).into()
    }
}
