use bytemuck::{TransparentWrapper, TransparentWrapperAlloc};
use noise_protocol::HandshakeStateBuilder;
use quinn_proto::crypto::{ClientConfig, KeyPair, Session};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, Side, TransportError};
use std::convert::TryInto;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::noise_impl::{HandshakeState, Sensitive};
use crate::NoiseClientConfig;

use super::{
    client_server, connection_refused, handshake_pattern, noise_error, split, split_n, CommonData,
    Data, NoiseSession, State,
};

fn client_keys(state: &HandshakeState) -> KeyPair<Sensitive<[u8; 32]>> {
    let (client, server) = client_server(state);
    KeyPair {
        local: client,
        remote: server,
    }
}

impl ClientConfig for NoiseClientConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let mut state = HandshakeStateBuilder::new();
        state
            .set_pattern(handshake_pattern())
            .set_prologue(&[])
            .set_s(Sensitive(Zeroizing::new(self.keypair.to_bytes())))
            .set_rs(self.remote_public_key.to_bytes())
            .set_is_initiator(true);
        let state = state.build_handshake_state();

        Ok(Box::new(NoiseSession {
            state: Ok(Box::new(ClientInitial { state })),
            data: CommonData {
                requested_protocols: self.requested_protocols.clone(),
                supported_protocols: vec![],
                transport_parameters: *params,
                remote_transport_parameters: None,
                remote_s: Some(self.remote_public_key),
            },
        }))
    }
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientInitial {
    state: HandshakeState,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientHandshake {
    state: HandshakeState,
}

#[derive(TransparentWrapper)]
#[repr(transparent)]
struct ClientOneRTT {
    data: Data,
}

impl State for ClientInitial {
    fn write_handshake(
        mut self: Box<Self>,
        data: &CommonData,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
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

impl State for ClientHandshake {
    fn read_handshake(
        mut self: Box<Self>,
        data: &mut CommonData,
        handshake: &[u8],
    ) -> Result<Box<dyn State>, TransportError> {
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
            data: Data {
                hash: self.state.get_hash().try_into().unwrap(),
                keys: client_keys(&self.state),
            },
        }))
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        (self, None)
    }
}

impl State for ClientOneRTT {
    fn write_handshake(
        mut self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        let keys = self.data.next_keys();
        (ClientOneRTT::peel_box(self), Some(keys))
    }
}
