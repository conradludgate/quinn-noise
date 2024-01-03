use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::crypto::{KeyPair, Keys, ServerConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::NoiseServerConfig;

use super::{
    client_server, connection_refused, initial_keys, noise_error, split, split_n, CommonData, Data,
    InnerHandshakeState, NoiseSession, State, RETRY_INTEGRITY_KEY, RETRY_INTEGRITY_NONCE,
};

fn server_keys<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> KeyPair<C::Key> {
    let (client, server) = client_server(state);
    KeyPair {
        local: server,
        remote: client,
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> ServerConfig
    for NoiseServerConfig<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(NoiseSession::<D, C, H> {
            state: Ok(Box::new(ServerRead {
                inner: InnerHandshakeState {
                    state: self.state.clone(),
                    pattern: 0,
                },
            })),
            data: CommonData {
                requested_protocols: vec![],
                supported_protocols: self.supported_protocols.clone(),
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: None,
            },
            hash: PhantomData,
        })
    }

    fn initial_keys(
        &self,
        _version: u32,
        _dst_cid: &ConnectionId,
        _side: Side,
    ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
        Ok(initial_keys::<C>())
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

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerRead<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerKeys<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerWrite<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ServerRead<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn read_handshake(
        mut self: Box<Self>,
        data: &mut CommonData<D>,
        handshake: &[u8],
    ) -> Result<Box<dyn State<D, C>>, TransportError> {
        debug_assert!(!self.inner.state.is_write_turn());

        let trailing = self
            .inner
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;
        self.inner.pattern += 1;

        data.remote_s = self.inner.state.get_rs();

        if self.inner.connection_parameters_request() {
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
        }

        Ok(ServerKeys::wrap_box(Self::peel_box(self)))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        (self, None)
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ServerKeys<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        let keys = server_keys(&self.inner.state);

        if self.inner.state.completed() {
            let mut data = Data::<C, H> {
                hash: H::Output::from_slice(self.inner.state.get_hash()),
                keys,
            };

            let keys = data.next_keys();
            (Box::new(data), Some(keys))
        } else {
            (ServerWrite::wrap_box(Self::peel_box(self)), Some(keys))
        }
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ServerWrite<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn write_handshake(
        mut self: Box<Self>,
        data: &CommonData<D>,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        debug_assert!(self.inner.state.is_write_turn());

        // payload
        let mut payload = vec![];

        if self.inner.connection_parameters_response() {
            // alpn
            if let [alpn] = &*data.requested_protocols {
                payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
                payload.extend_from_slice(alpn);
            }

            data.transport_parameters.write(&mut payload);
        }

        let overhead = self.inner.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);

        self.inner.state.write_message(&payload, handshake).unwrap();
        self.inner.pattern += 1;

        let keys = server_keys(&self.inner.state);
        if self.inner.state.completed() {
            let mut data = Data::<C, H> {
                hash: H::Output::from_slice(self.inner.state.get_hash()),
                keys,
            };

            let keys = data.next_keys();
            (Box::new(data), Some(keys))
        } else {
            (ServerRead::wrap_box(Self::peel_box(self)), Some(keys))
        }
    }
}
