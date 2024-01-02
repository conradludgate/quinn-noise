use quinn_proto::crypto::{KeyPair, Keys, ServerConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError};
use std::convert::TryInto;
use std::sync::Arc;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

use crate::noise_impl::{HandshakeState, Sensitive};
use crate::NoiseServerConfig;

use super::{
    client_server, connection_refused, handshake_pattern, initial_keys, noise_error, split,
    split_n, CommonData, Data, NoiseSession, State, RETRY_INTEGRITY_KEY, RETRY_INTEGRITY_NONCE,
};

fn server_keys(state: &HandshakeState) -> KeyPair<Sensitive<[u8; 32]>> {
    let (client, server) = client_server(state);
    KeyPair {
        local: server,
        remote: client,
    }
}

impl ServerConfig for NoiseServerConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        let handshake_state = HandshakeState::new(
            handshake_pattern(),
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
            data: CommonData {
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

        let nonce = ring::aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

struct ServerInitial {
    state: HandshakeState,
}

struct ServerZeroRTT {
    state: HandshakeState,
}

struct ServerHandshake {
    state: HandshakeState,
}

impl State for ServerInitial {
    fn read_handshake(
        mut self: Box<Self>,
        data: &mut CommonData,
        handshake: &[u8],
    ) -> Result<Box<dyn State>, TransportError> {
        let trailing = self
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;

        data.remote_s = self.state.get_rs().map(PublicKey::from);

        // alpn
        let (&[len], rest) = split_n(&trailing)?;
        let (mut alpns, mut transport_params) = split(rest, len as usize)?;

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
                    data.requested_protocols.push(alpn.to_vec());
                    break;
                }
            }
            if data.requested_protocols.is_empty() {
                return Err(connection_refused("unsupported alpn"));
            }
        }

        data.remote_transport_parameters = Some(TransportParameters::read(
            Side::Server,
            &mut transport_params,
        )?);

        Ok(Box::new(ServerZeroRTT { state: self.state }))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        (self, None)
    }
}

impl State for ServerZeroRTT {
    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        let keys = server_keys(&self.state);
        (Box::new(ServerHandshake { state: self.state }), Some(keys))
    }
}

impl State for ServerHandshake {
    fn write_handshake(
        mut self: Box<Self>,
        data: &CommonData,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
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

        let mut data = Data {
            hash: self.state.get_hash().try_into().unwrap(),
            keys: server_keys(&self.state),
        };

        let keys = data.next_keys();
        (Box::new(data), Some(keys))
    }
}
