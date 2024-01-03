use bytes::BytesMut;
use noise_protocol::Cipher;
use quinn_proto::crypto::{CryptoError, PacketKey};

pub struct PacketKeyWrapper<C: Cipher>(pub C::Key);

impl<C: Cipher> PacketKey for PacketKeyWrapper<C>
where
    C::Key: 'static + Send,
{
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, in_out) = buf.split_at_mut(header_len);
        C::encrypt_in_place(&self.0, packet, header, in_out, in_out.len() - C::tag_len());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let ciphertext_len = payload.len();
        let len = C::decrypt_in_place(&self.0, packet, header, payload, ciphertext_len)
            .map_err(|_| CryptoError)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        C::tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        match C::name() {
            "ChaChaPoly" => u64::MAX,
            "AESGCM" => 1 << 23,
            // conservative lower bound...
            // raise an issue if you are using a different cipher and this is not correct
            _ => 1 << 20,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match C::name() {
            "ChaChaPoly" => 1 << 36,
            "AESGCM" => 1 << 52,
            // conservative lower bound...
            // raise an issue if you are using a different cipher and this is not correct
            _ => 1 << 20,
        }
    }
}
