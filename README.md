# Noise for the quinn quic implementation

This is a fork of the `ipfs-rust/quinn-noise` project. It is a significant rewrite and is not compatible.

## Handshake pattern

`Noise_IK_25519_ChaChaPoly_BLAKE3`.

My intended usecase is similar to that of wireguard or SSH. The client will know the server's public key,
but the server will not know which client to initially expect.

```
IK:
    <- s
    ...
    -> e, es, s, ss  || client transport parameters || 0rtt-data
    <- e, ee, se     || server transport parameters || 1rtt-data
```

## Crypto algorithms

### DH functions

```
DH(key_pair, public_key) = x25519::diffie_hellman(key_pair, public_key)
DHLEN = 32
```

### Cipher functions

This deviates from common noise implementations for chacha20poly1305 by copying what TLS does and derives an IV too.
This IV is then XORed with the packet number to get the new IV. See section 5.3 (Per-Record Nonce) <https://datatracker.ietf.org/doc/rfc8446/>.

```
ENCRYPT(k, n, ad, plaintext) =
  let mut iv = [0; 12];
  blake3::derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet iv").update(&k).finalize_xof().fill(&mut iv);
  let key = blake3::derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet key", &k);
  iv[4..] ^= u64::to_be_bytes(n)
  chacha20poly1305_encrypt(key, iv, ad, plaintext)

DECRYPT(k, n, ad, plaintext) =
  let mut iv = [0; 12];
  blake3::derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet iv").update(&k).finalize_xof().fill(&mut iv);
  let key = blake3::derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 packet key", &k);
  iv[4..] ^= u64::to_be_bytes(n)
  chacha20poly1305_decrypt(key, iv, ad, plaintext)

REKEY(k) =
  blake3::derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 update key", &k)
```

### Hash functions.

This deviates from common noise implementations significantly. Noise specifies that you must use HKDF to derive new keys. Since I am using BLAKE3 in this implementation, I decided to use BLAKE3's KDF implementation instead.

```
HASH(data) = blake3(data)
HASHLEN = 32

// not actually HKDF. given I'm using Blake3 which has native KDF it felt applicable
// to use that.
HKDF(chaining_key, input_key_material, num_outputs, context) =
  blake3::Hasher::new_derive_key(
    format!("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 {context}"),
  )
  .update(chaining_key)
  .update(input_key_material)
  .finalize_xof()
  .fill(&mut [0; num_ouputs * 32])
```


## QUIC version

I am using `0xf0f0f2f1` as the only valid version number.

Reserved versions for original `quinn-noise` are `0xf0f0f2f[0-f]` [0].

- [0] https://github.com/quicwg/base-drafts/wiki/QUIC-Versions

## Retry mechanism

The retry mechanism is identical to what is specified in the quic-tls spec.

## License

MIT OR Apache-2.0
