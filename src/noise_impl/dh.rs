use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use super::Sensitive;

pub enum X25519 {}

impl noise_protocol::DH for X25519 {
    type Key = Sensitive<[u8; 32]>;
    type Pubkey = [u8; 32];
    type Output = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        Sensitive(Zeroizing::new(
            StaticSecret::random_from_rng(OsRng).to_bytes(),
        ))
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        let static_secret = StaticSecret::from(**k);
        *PublicKey::from(&static_secret).as_bytes()
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Result<Self::Output, ()> {
        let k = StaticSecret::from(**k);
        let pk = PublicKey::from(*pk);
        Ok(Sensitive(Zeroizing::new(k.diffie_hellman(&pk).to_bytes())))
    }
}
