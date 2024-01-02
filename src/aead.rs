use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, PacketKey};
use rand_core::OsRng;
use ring::aead;

pub fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
    KeyPair {
        local: Box::new(PlaintextHeaderKey),
        remote: Box::new(PlaintextHeaderKey),
    }
}

pub struct PlaintextHeaderKey;
impl HeaderKey for PlaintextHeaderKey {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        0
    }
}

const TAGLEN: usize = 16;

pub enum ChaCha20Poly1305 {}

impl noise_protocol::Cipher for ChaCha20Poly1305 {
    fn name() -> &'static str {
        "ChaChaPoly"
    }

    type Key = Sensitive<[u8; 32]>;

    fn encrypt(k: &Self::Key, nonce: u64, ad: &[u8], plaintext: &[u8], out: &mut [u8]) {
        assert!(plaintext.len().checked_add(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap(),
        );

        let (in_out, tag_out) = out.split_at_mut(plaintext.len());
        in_out.copy_from_slice(plaintext);

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());
    }

    fn encrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        plaintext_len: usize,
    ) -> usize {
        assert!(plaintext_len
            .checked_add(TAGLEN)
            .map_or(false, |l| l <= in_out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap(),
        );

        let (in_out, tag_out) = in_out[..plaintext_len + TAGLEN].split_at_mut(plaintext_len);
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(ad), in_out)
            .unwrap();
        tag_out.copy_from_slice(tag.as_ref());

        plaintext_len + TAGLEN
    }

    fn decrypt(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), ()> {
        assert!(ciphertext.len().checked_sub(TAGLEN) == Some(out.len()));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap(),
        );
        let mut in_out = ciphertext.to_vec();

        let out0 = key
            .open_in_place(nonce, aead::Aad::from(ad), &mut in_out)
            .map_err(|_| ())?;

        out[..out0.len()].copy_from_slice(out0);
        Ok(())
    }

    fn decrypt_in_place(
        k: &Self::Key,
        nonce: u64,
        ad: &[u8],
        in_out: &mut [u8],
        ciphertext_len: usize,
    ) -> Result<usize, ()> {
        assert!(ciphertext_len <= in_out.len());
        assert!(ciphertext_len >= TAGLEN);

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, k.as_slice()).unwrap(),
        );
        key.open_in_place(nonce, aead::Aad::from(ad), &mut in_out[..ciphertext_len])
            .map_err(|_| ())?;

        Ok(ciphertext_len - TAGLEN)
    }
}

impl PacketKey for Sensitive<[u8; 32]> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, in_out) = buf.split_at_mut(header_len);
        ChaCha20Poly1305::encrypt_in_place(self, packet, header, in_out, in_out.len() - 16);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let ciphertext_len = payload.len();
        let len = ChaCha20Poly1305::decrypt_in_place(self, packet, header, payload, ciphertext_len)
            .map_err(|_| CryptoError)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAGLEN
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        1 << 30
    }
}

use noise_protocol::{Cipher, U8Array};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Struct holding a value that is safely zeroed on drop.
pub struct Sensitive<A: U8Array + Zeroize>(pub Zeroizing<A>);

impl<A: U8Array + Zeroize> Sensitive<A> {
    pub fn from(a: Zeroizing<A>) -> Self {
        Sensitive(a)
    }
}

impl<A: U8Array + Zeroize> core::ops::Deref for Sensitive<A> {
    type Target = A;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: U8Array + Zeroize> core::ops::DerefMut for Sensitive<A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A> U8Array for Sensitive<A>
where
    A: Zeroize + U8Array,
{
    fn new() -> Self {
        Sensitive::from(Zeroizing::new(A::new()))
    }

    fn new_with(v: u8) -> Self {
        Sensitive::from(Zeroizing::new(A::new_with(v)))
    }

    fn from_slice(s: &[u8]) -> Self {
        Sensitive::from(Zeroizing::new(A::from_slice(s)))
    }

    fn len() -> usize {
        A::len()
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

pub enum X25519 {}

impl noise_protocol::DH for X25519 {
    type Key = Sensitive<[u8; 32]>;
    type Pubkey = [u8; 32];
    type Output = Sensitive<[u8; 32]>;

    fn name() -> &'static str {
        "25519"
    }

    fn genkey() -> Self::Key {
        Self::Key::from_slice(StaticSecret::random_from_rng(OsRng).as_bytes())
    }

    fn pubkey(k: &Self::Key) -> Self::Pubkey {
        let static_secret = StaticSecret::from(**k);
        *PublicKey::from(&static_secret).as_bytes()
    }

    fn dh(k: &Self::Key, pk: &Self::Pubkey) -> Result<Self::Output, ()> {
        let k = StaticSecret::from(**k);
        let pk = PublicKey::from(*pk);
        Ok(Self::Output::from_slice(k.diffie_hellman(&pk).as_bytes()))
    }
}

#[derive(Default, Clone)]
pub struct Blake3(blake3::Hasher);

impl noise_protocol::Hash for Blake3 {
    fn name() -> &'static str {
        "BLAKE3"
    }

    type Block = [u8; 64];
    type Output = Sensitive<[u8; 32]>;

    fn input(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn result(&mut self) -> Self::Output {
        Sensitive(Zeroizing::new(self.0.finalize().into()))
    }

    // TODO: maybe use blake3 kdf instead of hkdf?
}
