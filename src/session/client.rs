use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::crypto::{ClientConfig, KeyPair, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, Side, TransportError};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::NoiseClientConfig;

use super::{
    client_server, connection_refused, noise_error, split, split_n, CommonData, Data,
    InnerHandshakeState, NoiseSession, State,
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
        let remote_s = self.state.get_rs();
        Ok(Box::new(NoiseSession::<D, C, H> {
            state: Ok(Box::new(ClientWrite {
                inner: InnerHandshakeState {
                    state: self.state.clone(),
                    pattern: 0,
                },
            })),
            data: CommonData {
                requested_protocols: self.requested_protocols.clone(),
                supported_protocols: vec![],
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s,
            },
            hash: PhantomData,
        }))
    }
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientWrite<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientRead<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientKeys<D: DH, C: Cipher, H: Hash> {
    inner: InnerHandshakeState<D, C, H>,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientFinished<C: Cipher, H: Hash> {
    data: Data<C, H>,
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientWrite<D, C, H>
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

        let mut payload = vec![];

        if self.inner.connection_parameters_request() {
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
        }

        let overhead = self.inner.state.get_next_message_overhead();
        handshake.resize(overhead + payload.len(), 0);
        self.inner.state.write_message(&payload, handshake).unwrap();
        self.inner.pattern += 1;

        let keys = client_keys(&self.inner.state);
        (ClientRead::wrap_box(Self::peel_box(self)), Some(keys))
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientRead<D, C, H>
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

        if self.inner.connection_parameters_response() {
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
        }

        if self.inner.state.completed() {
            Ok(Box::new(ClientFinished {
                data: Data::<C, H> {
                    hash: H::Output::from_slice(self.inner.state.get_hash()),
                    keys: client_keys(&self.inner.state),
                },
            }))
        } else {
            Ok(ClientKeys::wrap_box(Self::peel_box(self)))
        }
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        (self, None)
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientKeys<D, C, H>
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
        let keys = client_keys(&self.inner.state);
        (ClientRead::wrap_box(Self::peel_box(self)), Some(keys))
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for ClientFinished<C, H>
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
        (Self::peel_box(self), Some(keys))
    }
}
