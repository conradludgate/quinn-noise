mod session;

use std::{sync::Arc, marker::PhantomData};

use noise_protocol::{DH, Cipher, Hash};

// https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
// reserved versions for quinn-noise 0xf0f0f2f[0-f]
//
// NOTE(conradludgate): I have changed the suffex from 0 to 1 to indicate that I have made changes
// to the specification from the original. This is not an authorative change as I don't have
// jurisdiction over this registered version set. But I am doing it anyway
pub const SUPPORTED_QUIC_VERSIONS: &[u32] = &[0xf0f0f2f1];
pub const DEFAULT_QUIC_VERSION: u32 = 0xf0f0f2f1;

pub struct NoiseClientConfig<D: DH, C: Cipher, H: Hash>  {
    /// Keypair to use.
    pub keypair: D::Key,
    /// The remote public key. This needs to be set.
    pub remote_public_key: D::Pubkey,
    /// Requested ALPN identifiers.
    pub requested_protocols: Vec<Vec<u8>>,

    pub algs: PhantomData<(C::Key, H::Output)>,
}

pub struct NoiseServerConfig<D: DH, C: Cipher, H: Hash> {
    /// Keypair to use.
    pub keypair: D::Key,

    /// Verifier for client static public keys
    pub remote_public_key_verifier: Arc<dyn PublicKeyVerifier<D>>,

    /// Supported ALPN identifiers.
    pub supported_protocols: Vec<Vec<u8>>,

    pub algs: PhantomData<(C::Key, H::Output)>,
}

pub trait PublicKeyVerifier<D: DH>: 'static + Send + Sync {
    fn verify(&self, key: &D::Pubkey) -> bool;
}

pub struct HandshakeData {
    pub alpn: Vec<u8>,
}
