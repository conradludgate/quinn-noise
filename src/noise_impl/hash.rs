use zeroize::Zeroizing;

use super::Sensitive;

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
}
