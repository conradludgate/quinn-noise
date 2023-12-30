mod aead;
mod dh;
mod keylog;
mod session;

pub use crate::aead::ChaCha20PacketKey;
pub use crate::keylog::{KeyLog, KeyLogFile};
pub use crate::session::{NoiseClientConfig, NoiseConfig, NoiseServerConfig, NoiseSession};
pub use ed25519_dalek::{SigningKey, VerifyingKey, SecretKey};

// https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
// reserved versions for quinn-noise 0xf0f0f2f[0-f]
//
// NOTE(conradludgate): I have changed the suffex from 0 to 1 to indicate that I have made changes
// to the specification from the original. This is not an authorative change as I don't have
// jurisdiction over this registered version set. But I am doing it anyway
pub const SUPPORTED_QUIC_VERSIONS: &[u32] = &[0xf0f0f2f1];
pub const DEFAULT_QUIC_VERSION: u32 = 0xf0f0f2f1;
