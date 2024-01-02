use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::crypto::{KeyPair, Keys, ServerConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::{NoiseServerConfig, PublicKeyVerifier};

use super::{
    client_server, connection_refused, initial_keys, noise_error, split, split_n, CommonData, Data,
    NoiseSession, State, RETRY_INTEGRITY_KEY, RETRY_INTEGRITY_NONCE,
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
            state: Ok(Box::new(ServerInitial {
                state: InnerState {
                    state: self.state.clone(),
                    remote_public_key_verifier: self.remote_public_key_verifier.clone(),
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

struct InnerState<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    remote_public_key_verifier: Arc<dyn PublicKeyVerifier<D>>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerInitial<D: DH, C: Cipher, H: Hash> {
    state: InnerState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerZeroRTT<D: DH, C: Cipher, H: Hash> {
    state: InnerState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ServerHandshake<D: DH, C: Cipher, H: Hash> {
    state: InnerState<D, C, H>,
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ServerInitial<D, C, H>
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
        let trailing = self
            .state
            .state
            .read_message_vec(handshake)
            .map_err(noise_error)?;

        let rs = self
            .state
            .state
            .get_rs()
            .expect("IK pattern has s in the client initial handshake message");

        if !self.state.remote_public_key_verifier.verify(&rs) {
            return Err(connection_refused("client not authorized"));
        }

        data.remote_s = Some(rs);

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

        Ok(ServerZeroRTT::wrap_box(ServerInitial::peel_box(self)))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        (self, None)
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ServerZeroRTT<D, C, H>
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
        let keys = server_keys(&self.state.state);

        (
            ServerHandshake::wrap_box(ServerZeroRTT::peel_box(self)),
            Some(keys),
        )
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C>
    for ServerHandshake<D, C, H>
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
        // payload
        let mut payload = vec![];

        // alpn
        if let [alpn] = &*data.requested_protocols {
            payload.extend_from_slice(&(alpn.len() as u8).to_le_bytes());
            payload.extend_from_slice(alpn);
        }

        data.transport_parameters.write(&mut payload);

        let overhead = self.state.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);
        self.state.state.write_message(&payload, handshake).unwrap();

        let mut data = Data::<C, H> {
            hash: H::Output::from_slice(self.state.state.get_hash()),
            keys: server_keys(&self.state.state),
        };

        let keys = data.next_keys();
        (Box::new(data), Some(keys))
    }
}
