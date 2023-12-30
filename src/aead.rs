use std::convert::TryInto;

use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, PacketKey};
use ring::aead;

pub fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
    KeyPair {
        local: Box::new(PlaintextHeaderKey),
        remote: Box::new(PlaintextHeaderKey),
    }
}

#[derive(Clone)]
pub struct ChaCha20PacketKey {
    key: aead::LessSafeKey,
    iv: [u8; 12],
}

impl ChaCha20PacketKey {
    pub fn new(key: [u8; 44]) -> Self {
        let (key, iv) = key.split_at(32);
        let iv = iv.try_into().unwrap();
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).unwrap(),
            ),
            iv,
        }
    }
}

impl PacketKey for ChaCha20PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());

        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet, &self.iv);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, payload)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let payload_len = payload.len();
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet, &self.iv);

        self.key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| CryptoError)?;

        let plain_len = payload_len - self.key.algorithm().tag_len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
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

/// Compute the nonce to use for encrypting or decrypting `packet_number`
fn nonce_for(packet_number: u64, iv: &[u8; 12]) -> ring::aead::Nonce {
    let mut out = [0; aead::NONCE_LEN];
    out[4..].copy_from_slice(&packet_number.to_be_bytes());
    for (out, inp) in out.iter_mut().zip(iv.iter()) {
        *out ^= inp;
    }
    aead::Nonce::assume_unique_for_key(out)
}
