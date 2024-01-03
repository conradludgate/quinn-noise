use noise_protocol::{Cipher, Hash, U8Array, DH};
use quinn_proto::crypto::{ClientConfig, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::ConnectError;
use std::sync::Arc;

use crate::NoiseClientConfig;

use super::{CommonData, InnerHandshakeState, NoiseSession};

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> ClientConfig
    for NoiseClientConfig<D, C, H>
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
        let remote_s = self.state.get_rs();
        Ok(Box::new(NoiseSession::<D, C, H> {
            state: super::State::Handshaking(Box::new(InnerHandshakeState {
                state: self.state.clone(),
                pattern: 0,
                needs_keys: false,
            })),
            data: CommonData {
                negotiated_protocol: None,
                supported_protocols: self.requested_protocols.clone(),
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s,
            },
            integrity_key: self.integrity_key.clone(),
        }))
    }
}
