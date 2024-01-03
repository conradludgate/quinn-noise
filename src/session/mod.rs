use noise_protocol::{Cipher, HandshakeState, Hash, U8Array, DH};
use quinn_proto::crypto::{
    ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};
use ring::aead;
use std::any::Any;
use std::convert::TryInto;
use std::marker::PhantomData;

use crate::HandshakeData;

use self::packet_key::PacketKeyWrapper;

mod client;
mod packet_key;
mod server;

fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
    struct PlaintextHeaderKey;
    impl HeaderKey for PlaintextHeaderKey {
        fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

        fn sample_size(&self) -> usize {
            0
        }
    }

    KeyPair {
        local: Box::new(PlaintextHeaderKey),
        remote: Box::new(PlaintextHeaderKey),
    }
}

fn packet_keys<C: Cipher + 'static>(keys: KeyPair<C::Key>) -> KeyPair<Box<dyn PacketKey>>
where
    C::Key: 'static + Send,
{
    KeyPair {
        local: Box::new(PacketKeyWrapper::<C>(keys.local)),
        remote: Box::new(PacketKeyWrapper::<C>(keys.remote)),
    }
}

fn initial_keys<C: Cipher + 'static>() -> Keys
where
    C::Key: 'static + Send,
{
    Keys {
        header: header_keypair(),
        packet: packet_keys::<C>(KeyPair {
            local: C::Key::new(),
            remote: C::Key::new(),
        }),
    }
}

trait State<D: DH, C: Cipher>: 'static + Send + Sync {
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<C::Key>> {
        None
    }

    fn read_handshake(
        self: Box<Self>,
        _data: &mut CommonData<D>,
        _handshake: &[u8],
    ) -> Result<Box<dyn State<D, C>>, TransportError> {
        Err(TransportError {
            code: TransportErrorCode::CONNECTION_REFUSED,
            frame: None,
            reason: "unexpected crypto frame".to_string(),
        })
    }

    #[allow(clippy::type_complexity)]
    fn write_handshake(
        self: Box<Self>,
        data: &CommonData<D>,
        handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>);

    fn is_handshaking(&self) -> bool {
        true
    }

    fn get_channel_binding(&self) -> &[u8] {
        &[]
    }
}

fn client_server<D: DH, C: Cipher, H: Hash>(state: &HandshakeState<D, C, H>) -> (C::Key, C::Key) {
    let (client, server) = state.get_ciphers();
    let (client, 0) = client.extract() else {
        panic!("expected nonce to be 0")
    };
    let (server, 0) = server.extract() else {
        panic!("expected nonce to be 0")
    };
    (client, server)
}

struct InnerHandshakeState<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    // a little bit annoying that neither snow nor noise-protocol expose this field directly
    pattern: usize,
}

impl<D: DH, C: Cipher, H: Hash> InnerHandshakeState<D, C, H> {
    fn connection_parameters_request(&self) -> bool {
        self.pattern + 3 >= self.state.get_pattern().get_message_patterns_len()
    }
    fn connection_parameters_response(&self) -> bool {
        self.pattern + 2 >= self.state.get_pattern().get_message_patterns_len()
    }
}

struct Data<C: Cipher, H: Hash> {
    keys: KeyPair<C::Key>,
    hash: H::Output,
}

impl<C: Cipher, H: Hash> Data<C, H> {
    fn next_keys(&mut self) -> KeyPair<C::Key> {
        let KeyPair { local, remote } = &mut self.keys;
        let next_local = C::rekey(local);
        let next_remote = C::rekey(remote);
        KeyPair {
            local: std::mem::replace(local, next_local),
            remote: std::mem::replace(remote, next_remote),
        }
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> State<D, C> for Data<C, H>
where
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<C::Key>> {
        Some(self.next_keys())
    }

    fn write_handshake(
        self: Box<Self>,
        _data: &CommonData<D>,
        _handshake: &mut Vec<u8>,
    ) -> (Box<dyn State<D, C>>, Option<KeyPair<C::Key>>) {
        (self, None)
    }

    fn is_handshaking(&self) -> bool {
        false
    }

    fn get_channel_binding(&self) -> &[u8] {
        self.hash.as_slice()
    }
}

struct NoiseSession<D: DH, C: Cipher, H: Hash> {
    state: Result<Box<dyn State<D, C>>, TransportError>,
    data: CommonData<D>,
    hash: PhantomData<H::Output>,
}

struct CommonData<D: DH> {
    requested_protocols: Vec<Vec<u8>>,
    supported_protocols: Vec<Vec<u8>>,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
    remote_s: Option<D::Pubkey>,
}

fn connection_refused(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame: None,
        reason: reason.to_string(),
    }
}

fn split(data: &[u8], n: usize) -> Result<(&[u8], &[u8]), TransportError> {
    if data.len() < n {
        Err(connection_refused("invalid crypto frame"))
    } else {
        Ok(data.split_at(n))
    }
}

fn split_n<const N: usize>(data: &[u8]) -> Result<(&[u8; N], &[u8]), TransportError> {
    let (n, data) = split(data, N)?;
    Ok((n.try_into().unwrap(), data))
}

fn noise_error(e: noise_protocol::Error) -> TransportError {
    match e.kind() {
        noise_protocol::ErrorKind::DH => {
            unreachable!("this diffie-hellman implementation cannot fail")
        }
        noise_protocol::ErrorKind::NeedPSK => {
            unreachable!("this noise implementation should not need PSK")
        }
        noise_protocol::ErrorKind::Decryption => {
            connection_refused("could not decrypt handshake message")
        }
        noise_protocol::ErrorKind::TooShort => connection_refused("handshake message is too short"),
    }
}

impl<D: DH + 'static, C: Cipher + 'static, H: Hash + 'static> Session for NoiseSession<D, C, H>
where
    D::Pubkey: 'static + Send + Sync,
    D::Key: 'static + Send + Sync,
    C::Key: 'static + Send + Sync,
    H::Output: 'static + Send + Sync,
{
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        initial_keys::<C>()
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.state
            .as_mut()
            .unwrap()
            .next_1rtt_keys()
            .map(packet_keys::<C>)
    }

    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        self.state = Ok(std::mem::replace(
            &mut self.state,
            Err(connection_refused("broken poison state")),
        )?
        .read_handshake(&mut self.data, handshake)?);

        Ok(!self.data.requested_protocols.is_empty())
    }

    fn write_handshake(&mut self, handshake: &mut Vec<u8>) -> Option<Keys> {
        let (state, keys) = std::mem::replace(
            &mut self.state,
            Err(connection_refused("broken poison state")),
        )
        .unwrap()
        .write_handshake(&self.data, handshake);

        self.state = Ok(state);

        keys.map(|keys| Keys {
            header: header_keypair(),
            packet: packet_keys::<C>(keys),
        })
    }

    fn is_handshaking(&self) -> bool {
        self.state.as_ref().unwrap().is_handshaking()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.data.remote_s.as_ref()?.clone()))
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(Some(
            self.data
                .remote_transport_parameters
                .unwrap_or(self.data.transport_parameters),
        ))
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(HandshakeData {
            alpn: self.data.requested_protocols.get(0)?.clone(),
        }))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        if output.is_empty() {
            return Ok(());
        }
        if output.len() > H::hash_len() * 255 {
            return Err(ExportKeyingMaterialError);
        }

        let hash = self.state.as_ref().unwrap().get_channel_binding();

        let mut chunks = output.chunks_mut(H::hash_len()).enumerate();
        let (i, chunk) = chunks.next().unwrap();
        let mut out = H::hmac_many(hash, &[label, context, &[(i + 1) as u8]]);
        chunk.copy_from_slice(&out.as_slice()[..chunk.len()]);

        for (i, chunk) in chunks {
            out = H::hmac_many(hash, &[label, context, out.as_slice(), &[(i + 1) as u8]]);
            chunk.copy_from_slice(&out.as_slice()[..chunk.len()]);
        }

        Ok(())
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(true)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];
