mod session;

use std::{marker::PhantomData, sync::Arc};

use noise_protocol::{
    patterns::{HandshakePattern, Token},
    Cipher, HandshakeState, HandshakeStateBuilder, Hash, DH,
};

pub struct NoiseClientConfig<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    requested_protocols: Vec<Vec<u8>>,
}

pub struct NoiseServerConfig<D: DH, C: Cipher, H: Hash> {
    state: HandshakeState<D, C, H>,
    remote_public_key_verifier: Arc<dyn PublicKeyVerifier<D>>,
    supported_protocols: Vec<Vec<u8>>,
}

fn handshake_pattern<D: DH, C: Cipher, H: Hash>() -> HandshakePattern {
    let name = String::leak(format!(
        "Noise_IK_{}_{}_{}",
        D::name(),
        C::name(),
        H::name()
    ));

    HandshakePattern::new(
        &[],
        &[Token::S],
        &[
            &[Token::E, Token::ES, Token::S, Token::SS],
            &[Token::E, Token::EE, Token::SE],
        ],
        name,
    )
}

impl<D: DH, C: Cipher, H: Hash> NoiseServerConfig<D, C, H> {
    pub fn builder(prologue: &[u8]) -> NoiseServerConfigBuilder<'_, D, C, H> {
        let mut builder = HandshakeStateBuilder::<D>::new();
        builder
            .set_pattern(handshake_pattern::<D, C, H>())
            .set_prologue(prologue)
            .set_is_initiator(false);
        NoiseServerConfigBuilder {
            builder,
            remote_public_key_verifier: Arc::new(NoVerify),
            supported_protocols: vec![],
            algs: PhantomData,
        }
    }
}

pub struct NoiseServerConfigBuilder<'a, D: DH, C: Cipher, H: Hash> {
    builder: HandshakeStateBuilder<'a, D>,
    remote_public_key_verifier: Arc<dyn PublicKeyVerifier<D>>,
    supported_protocols: Vec<Vec<u8>>,
    algs: PhantomData<(C::Key, H::Output)>,
}

impl<D: DH, C: Cipher, H: Hash> NoiseServerConfigBuilder<'_, D, C, H> {
    pub fn set_static_key(mut self, key: D::Key) -> Self {
        self.builder.set_s(key);
        self
    }

    pub fn set_key_verifier(mut self, v: Arc<dyn PublicKeyVerifier<D>>) -> Self {
        self.remote_public_key_verifier = v;
        self
    }

    pub fn push_supported_protocol(mut self, alpn: Vec<u8>) -> Self {
        self.supported_protocols.push(alpn);
        self
    }

    pub fn build(self) -> NoiseServerConfig<D, C, H> {
        NoiseServerConfig {
            state: self.builder.build_handshake_state(),
            remote_public_key_verifier: self.remote_public_key_verifier,
            supported_protocols: self.supported_protocols,
        }
    }
}

impl<D: DH, C: Cipher, H: Hash> NoiseClientConfig<D, C, H> {
    pub fn builder(prologue: &[u8]) -> NoiseClientConfigBuilder<'_, D, C, H> {
        let mut builder = HandshakeStateBuilder::<D>::new();
        builder
            .set_pattern(handshake_pattern::<D, C, H>())
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
        NoiseClientConfig {
            state: self.builder.build_handshake_state(),
            requested_protocols: self.requested_protocols,
        }
    }
}

pub trait PublicKeyVerifier<D: DH>: 'static + Send + Sync {
    fn verify(&self, key: &D::Pubkey) -> bool;
}

pub struct HandshakeData {
    pub alpn: Vec<u8>,
}

struct NoVerify;
impl<D: DH> PublicKeyVerifier<D> for NoVerify {
    fn verify(&self, _key: &<D as DH>::Pubkey) -> bool {
        true
    }
}
