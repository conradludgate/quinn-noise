use quinn_proto::crypto::{ClientConfig, KeyPair, PacketKey, Session};
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
        let handshake_state = HandshakeState::new(
            handshake_pattern(),
            true,
            [],
            Some(Sensitive(Zeroizing::new(self.keypair.to_bytes()))),
            None,
            Some(self.remote_public_key.to_bytes()),
            None,
        );

        Ok(Box::new(NoiseSession {
            state: Ok(Box::new(ClientInitial {
                state: handshake_state,
            })),
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

struct ClientInitial {
    state: HandshakeState,
}

struct ClientZeroRTT {
    state: HandshakeState,
}

struct ClientHandshake {
    state: HandshakeState,
}

struct ClientOneRTT {
    keys: KeyPair<Sensitive<[u8; 32]>>,
    hash: [u8; 32],
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

        (Box::new(ClientZeroRTT { state: self.state }), None)
    }
}

impl State for ClientZeroRTT {
    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        let keys = client_keys(&self.state);
        (Box::new(ClientHandshake { state: self.state }), Some(keys))
    }
}

impl State for ClientHandshake {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }

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
            hash: self.state.get_hash().try_into().unwrap(),
            keys: client_keys(&self.state),
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
        self: Box<Self>,
        _data: &CommonData,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State>, Option<KeyPair<Sensitive<[u8; 32]>>>) {
        let mut data = Data {
            hash: self.hash,
            keys: self.keys,
        };

        let keys = data.next_keys();
        (Box::new(data), Some(keys))
    }

    fn get_channel_binding(&self) -> &[u8] {
        &self.hash
    }
}
