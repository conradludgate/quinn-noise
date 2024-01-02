use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use noise_protocol::{Cipher, HandshakeState, HandshakeStateBuilder, Hash, U8Array, DH};
use quinn_proto::crypto::{ClientConfig, KeyPair, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, Side, TransportError};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::NoiseClientConfig;

use super::{
    client_server, connection_refused, handshake_pattern, noise_error, split, split_n, CommonData,
    Data, NoiseSession, State,
};

fn client_keys<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> KeyPair<C::Key> {
    let (client, server) = client_server(state);
    KeyPair {
        local: client,
        remote: server,
    }
}

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
        let mut state = HandshakeStateBuilder::<D>::new();
        state
            .set_pattern(handshake_pattern::<D, C, H>())
            .set_prologue(&[])
            .set_s(self.keypair.clone())
            .set_rs(self.remote_public_key.clone())
            .set_is_initiator(true);
        let state = state.build_handshake_state::<C, H>();

        Ok(Box::new(NoiseSession::<D, C, H> {
            state: Ok(Box::new(ClientInitial { state })),
            data: CommonData {
                requested_protocols: self.requested_protocols.clone(),
                supported_protocols: vec![],
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: Some(self.remote_public_key.clone()),
            },
            hash: PhantomData,
        }))
    }
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientInitial<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientHandshake<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientOneRTT<C: Cipher, H: Hash> {
    data: Data<C, H>,
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientInitial<D, C, H>
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

        let keys = client_keys(&self.state);
        (
            ClientHandshake::wrap_box(ClientInitial::peel_box(self)),
            Some(keys),
        )
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C>
    for ClientHandshake<D, C, H>
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
            .read_message_vec(handshake)
            .map_err(noise_error)?;

        // alpn
        let (&[len], rest) = split_n(&trailing)?;
        let (alpn, mut transport_params) = split(rest, len as usize)?;
        if !data.requested_protocols.is_empty() {
            if alpn.is_empty() {
                return Err(connection_refused("unsupported alpn"));
            }
            data.requested_protocols.retain(|x| x == alpn);
        }

        data.remote_transport_parameters = Some(TransportParameters::read(
            Side::Client,
            &mut transport_params,
        )?);

        Ok(Box::new(ClientOneRTT {
            data: Data::<C, H> {
                hash: H::Output::from_slice(self.state.get_hash()),
                keys: client_keys(&self.state),
            },
        }))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        (self, None)
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientOneRTT<C, H>
where
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn write_handshake(
        mut self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        let keys = self.data.next_keys();
        (ClientOneRTT::peel_box(self), Some(keys))
    }
}
