mod packet_key;
mod session;

use std::sync::Arc;

pub use noise_protocol;

use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::{
    crypto::{ClientConfig, Keys, ServerConfig, Session},
    transport_parameters::TransportParameters,
    ConnectError, ConnectionId, Side,
};
use session::{get_integrity_key, initial_keys};

use crate::session::{InnerHandshakeState, NoiseSession, State};

pub struct NoiseConfig<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    supported_protocols: Vec<Vec<u8>>,
    integrity_key: H::Output,
}

impl<D: DH, C: Cipher, H: Hash> NoiseConfig<D, C, H> {
    pub fn new(
        handshake: HandshakeState<D, C, H>,
        protocols: Vec<Vec<u8>>,
    ) -> NoiseConfig<D, C, H> {
        let integrity_key = get_integrity_key(&handshake);
        NoiseConfig {
            state: handshake,
            integrity_key,
            supported_protocols: protocols,
        }
    }
}

pub struct HandshakeData {
    pub alpn: Vec<u8>,
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> ServerConfig for NoiseConfig<D, C, H>
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
        assert!(!self.state.get_is_initiator());

        Box::new(NoiseSession::<D, C, H> {
            state: State::Handshaking(Box::new(InnerHandshakeState {
                state: self.state.clone(),
                pattern: 0,
                needs_keys: false,
            })),
            negotiated_protocol: None,
            supported_protocols: self.supported_protocols.clone(),
            transport_parameters: *params,
            remote_transport_parameters: None,
            remote_s: None,

            integrity_key: self.integrity_key.clone(),
        })
    }

    fn initial_keys(
        &self,
        _version: u32,
        _dst_cid: &ConnectionId,
        _side: Side,
    ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
        Ok(initial_keys(&self.state))
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let tag = H::hmac_many(
            self.integrity_key.as_slice(),
            &[&[orig_dst_cid.len() as u8], orig_dst_cid, packet],
        );

        let mut result = [0; 16];
        result.copy_from_slice(tag.as_slice());
        result
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> ClientConfig for NoiseConfig<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        assert!(self.state.get_is_initiator());

        Ok(Box::new(NoiseSession::<D, C, H> {
            state: State::Handshaking(Box::new(InnerHandshakeState {
                state: self.state.clone(),
                pattern: 0,
                needs_keys: false,
            })),
            negotiated_protocol: None,
            supported_protocols: self.supported_protocols.clone(),
            transport_parameters: *params,
            remote_transport_parameters: None,
            remote_s: None,

            integrity_key: self.integrity_key.clone(),
        }))
    }
}
