mod session;

use std::marker::PhantomData;

use noise_protocol::{patterns::noise_ik, Cipher, HandshakeState, HandshakeStateBuilder, Hash, DH};
use session::get_integrity_key;

pub struct NoiseClientConfig<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    requested_protocols: Vec<Vec<u8>>,
    integrity_key: H::Output,
}

pub struct NoiseServerConfig<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    supported_protocols: Vec<Vec<u8>>,
    integrity_key: H::Output,
}

impl<D: DH, C: Cipher, H: Hash> NoiseServerConfig<D, C, H> {
    pub fn builder(prologue: &[u8]) -> NoiseServerConfigBuilder<'_, D, C, H> {
        let mut builder = HandshakeStateBuilder::<D>::new();
        builder
            .set_pattern(noise_ik())
            .set_prologue(prologue)
            .set_is_initiator(false);
        NoiseServerConfigBuilder {
            builder,
            supported_protocols: vec![],
            algs: PhantomData,
        }
    }
}

pub struct NoiseServerConfigBuilder<'a, D: DH, C: Cipher, H: Hash> {
    builder: HandshakeStateBuilder<'a, D>,
    supported_protocols: Vec<Vec<u8>>,
    algs: PhantomData<(C::Key, H::Output)>,
}

impl<D: DH, C: Cipher, H: Hash> NoiseServerConfigBuilder<'_, D, C, H> {
    pub fn set_static_key(mut self, key: D::Key) -> Self {
        self.builder.set_s(key);
        self
    }

    pub fn push_supported_protocol(mut self, alpn: Vec<u8>) -> Self {
        self.supported_protocols.push(alpn);
        self
    }

    pub fn build(self) -> NoiseServerConfig<D, C, H> {
        let state = self.builder.build_handshake_state();
        let integrity_key = get_integrity_key(&state);
        NoiseServerConfig {
            state,
            integrity_key,
            supported_protocols: self.supported_protocols,
        }
    }
}

impl<D: DH, C: Cipher, H: Hash> NoiseClientConfig<D, C, H> {
    pub fn builder(prologue: &[u8]) -> NoiseClientConfigBuilder<'_, D, C, H> {
        let mut builder = HandshakeStateBuilder::<D>::new();
        builder
            .set_pattern(noise_ik())
            .set_prologue(prologue)
            .set_is_initiator(true);
        NoiseClientConfigBuilder {
            builder,
            requested_protocols: vec![],
            algs: PhantomData,
        }
    }
}

pub struct NoiseClientConfigBuilder<'a, D: DH, C: Cipher, H: Hash> {
    builder: HandshakeStateBuilder<'a, D>,
    requested_protocols: Vec<Vec<u8>>,
    algs: PhantomData<(C::Key, H::Output)>,
}

impl<D: DH, C: Cipher, H: Hash> NoiseClientConfigBuilder<'_, D, C, H> {
    pub fn set_static_key(mut self, key: D::Key) -> Self {
        self.builder.set_s(key);
        self
    }

    pub fn set_remote_public_key(mut self, key: D::Pubkey) -> Self {
        self.builder.set_rs(key);
        self
    }

    pub fn push_requested_protocol(mut self, alpn: Vec<u8>) -> Self {
        self.requested_protocols.push(alpn);
        self
    }

    pub fn build(self) -> NoiseClientConfig<D, C, H> {
        let state = self.builder.build_handshake_state();
        let integrity_key = get_integrity_key(&state);
        NoiseClientConfig {
            state,
            integrity_key,
            requested_protocols: self.requested_protocols,
        }
    }
}

pub struct HandshakeData {
    pub alpn: Vec<u8>,
}
