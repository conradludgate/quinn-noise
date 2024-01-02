mod noise_impl;
mod session;

use std::sync::Arc;

pub use x25519_dalek::{PublicKey, StaticSecret};

// https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
// reserved versions for quinn-noise 0xf0f0f2f[0-f]
//
// NOTE(conradludgate): I have changed the suffex from 0 to 1 to indicate that I have made changes
// to the specification from the original. This is not an authorative change as I don't have
// jurisdiction over this registered version set. But I am doing it anyway
pub const SUPPORTED_QUIC_VERSIONS: &[u32] = &[0xf0f0f2f1];
pub const DEFAULT_QUIC_VERSION: u32 = 0xf0f0f2f1;

pub struct NoiseClientConfig {
    /// Keypair to use.
    pub keypair: StaticSecret,
    /// The remote public key. This needs to be set.
    pub remote_public_key: PublicKey,
    /// Requested ALPN identifiers.
    pub requested_protocols: Vec<Vec<u8>>,
}

pub struct NoiseServerConfig {
    /// Keypair to use.
    pub keypair: StaticSecret,

    /// Verifier for client static public keys
    pub remote_public_key_verifier: Arc<dyn PublicKeyVerifier>,

    /// Supported ALPN identifiers.
    pub supported_protocols: Vec<Vec<u8>>,
}

pub trait PublicKeyVerifier: 'static + Send + Sync {
    fn verify(&self, key: &PublicKey) -> bool;
}

pub struct HandshakeData {
    pub alpn: Vec<u8>,
}
