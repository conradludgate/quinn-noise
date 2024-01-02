use std::convert::TryFrom;

use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, PacketKey};
use ring::aead::{self, Tag};

#[derive(Clone)]
pub struct ChaCha20PacketKey {
    key: aead::LessSafeKey,
    iv: [u8; 12],
}

impl ChaCha20PacketKey {
    pub fn new(key: [u8; 32]) -> Self {
        let mut iv = [0; 12];
        blake3::Hasher::new_derive_key(
            "QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet iv",
        )
        .update(&key)
        .finalize_xof()
        .fill(&mut iv);
        let key = blake3::derive_key(
            "QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet key",
            &key,
        );
        Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap(),
            ),
            iv,
        }
    }
}

impl ChaCha20PacketKey {
    pub fn encrypt_ad(&self, packet: u64, header: &[u8], payload_tag: &mut [u8]) {
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());

        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet, &self.iv);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, payload)
            .unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    pub fn decrypt_ad(
        &self,
        packet: u64,
        header: &[u8],
        tag: &[u8],
        payload: &mut [u8],
    ) -> Result<(), CryptoError> {
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet, &self.iv);
        let tag = Tag::try_from(tag).map_err(|_| CryptoError)?;

        self.key
            .open_in_place_separate_tag(nonce, aad, tag, payload, 0..)
            .map_err(|_| CryptoError)?;

        Ok(())
    }

    /// Encrypt a QUIC packet
    ///
    /// Takes a `packet_number`, used to derive the nonce; the packet `header`, which is used as
    /// the additional authenticated data; and the `payload`. The authentication tag is returned if
    /// encryption succeeds.
    ///
    /// Fails iff the payload is longer than allowed by the cipher suite's AEAD algorithm.
    fn encrypt_in_place(&self, packet_number: u64, header: &[u8], payload: &mut [u8]) -> Tag {
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet_number, &self.iv);
        self.key
            .seal_in_place_separate_tag(nonce, aad, payload)
            .unwrap()
    }

    /// Decrypt a QUIC packet
    ///
    /// Takes the packet `header`, which is used as the additional authenticated data, and the
    /// `payload`, which includes the authentication tag.
    ///
    /// If the return value is `Ok`, the decrypted payload can be found in `payload`, up to the
    /// length found in the return value.
    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let payload_len = payload.len();
        let aad = aead::Aad::from(header);
        let nonce = nonce_for(packet_number, &self.iv);
        self.key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| CryptoError)?;

        let plain_len = payload_len - self.key.algorithm().tag_len();
        Ok(&payload[..plain_len])
    }
}

impl PacketKey for ChaCha20PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self.encrypt_in_place(packet, &*header, payload);
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let plain = self
            .decrypt_in_place(packet, header, payload.as_mut())
            .map_err(|_| CryptoError)?;
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.key.algorithm().tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        1 << 30
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

/// A QUIC header protection key
pub struct HeaderProtectionKey(aead::quic::HeaderProtectionKey);

impl HeaderProtectionKey {
    pub fn new(ikm: [u8; 32]) -> Self {
        let key = blake3::derive_key(
            "QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 header key",
            &ikm,
        );
        Self(aead::quic::HeaderProtectionKey::new(&aead::quic::CHACHA20, &key).unwrap())
    }

    /// Adds QUIC Header Protection.
    ///
    /// `sample` must contain the sample of encrypted payload; see
    /// [Header Protection Sample].
    ///
    /// `first` must reference the first byte of the header, referred to as
    /// `packet[0]` in [Header Protection Application].
    ///
    /// `packet_number` must reference the Packet Number field; this is
    /// `packet[pn_offset:pn_offset+pn_length]` in [Header Protection Application].
    ///
    /// Returns an error without modifying anything if `sample` is not
    /// the correct length (see [Header Protection Sample] and [`Self::sample_len()`]),
    /// or `packet_number` is longer than allowed (see [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection added.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn encrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) {
        self.xor_in_place(sample, first, packet_number, false)
    }

    /// Removes QUIC Header Protection.
    ///
    /// `sample` must contain the sample of encrypted payload; see
    /// [Header Protection Sample].
    ///
    /// `first` must reference the first byte of the header, referred to as
    /// `packet[0]` in [Header Protection Application].
    ///
    /// `packet_number` must reference the Packet Number field; this is
    /// `packet[pn_offset:pn_offset+pn_length]` in [Header Protection Application].
    ///
    /// Returns an error without modifying anything if `sample` is not
    /// the correct length (see [Header Protection Sample] and [`Self::sample_len()`]),
    /// or `packet_number` is longer than allowed (see
    /// [Packet Number Encoding and Decoding]).
    ///
    /// Otherwise, `first` and `packet_number` will have the header protection removed.
    ///
    /// [Header Protection Application]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.1
    /// [Header Protection Sample]: https://datatracker.ietf.org/doc/html/rfc9001#section-5.4.2
    /// [Packet Number Encoding and Decoding]: https://datatracker.ietf.org/doc/html/rfc9000#section-17.1
    #[inline]
    pub fn decrypt_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn xor_in_place(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8], masked: bool) {
        // This implements [Header Protection Application] almost verbatim.

        let mask = self.0.new_mask(sample).unwrap();

        // The `unwrap()` will not panic because `new_mask` returns a
        // non-empty result.
        let (first_mask, pn_mask) = mask.split_first().unwrap();

        assert!(
            packet_number.len() <= pn_mask.len(),
            "packet number too long"
        );

        // Infallible from this point on. Before this point, `first` and
        // `packet_number` are unchanged.

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = match *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            true => 0x0f,  // Long header: 4 bits masked
            false => 0x1f, // Short header: 5 bits masked
        };

        let first_plain = match masked {
            // When unmasking, use the packet length bits after unmasking
            true => *first ^ (first_mask & bits),
            // When masking, use the packet length bits before masking
            false => *first,
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
    }

    /// Expected sample length for the key's algorithm
    #[inline]
    pub fn sample_len(&self) -> usize {
        self.0.algorithm().sample_len()
    }
}

impl HeaderKey for HeaderProtectionKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        );
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        );
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}
