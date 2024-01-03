use noise_protocol::{Cipher, Hash, U8Array, DH};
use quinn_proto::crypto::{Keys, ServerConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side};
use std::sync::Arc;

use crate::NoiseServerConfig;

use super::{initial_keys, CommonData, InnerHandshakeState, NoiseSession};

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
            state: super::State::Handshaking(Box::new(InnerHandshakeState {
                state: self.state.clone(),
                pattern: 0,
                needs_keys: false,
            })),
            data: CommonData {
                negotiated_protocol: None,
                supported_protocols: self.supported_protocols.clone(),
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: None,
            },
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
