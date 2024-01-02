# Noise for the quinn quic implementation

This is a fork of the `ipfs-rust/quinn-noise` project. It is a significant rewrite and is not compatible.

## Handshake pattern

`Noise_IK_25519_ChaChaPoly_BLAKE3`.

My intended usecase is similar to that of wireguard or SSH. The client will know the server's public key,
but the server will not know which client to initially expect. Because of this, I am using the `IK` pattern

* `I` - Static key for initiator Immediately transmitted to responder, despite reduced or absent identity hiding
* `K` - Static key for responder Known to initiator

```
IK:
    <- s
    ...
    -> e, es, s, ss  || client transport parameters || 0rtt-data
    <- e, ee, se     || server transport parameters || 1rtt-data
```

## QUIC version

I am using `0xf0f0f2f1` as the only valid version number.

Reserved versions for original `quinn-noise` are `0xf0f0f2f[0-f]` [0].

- [0] https://github.com/quicwg/base-drafts/wiki/QUIC-Versions

## Export Keying Material

The final SymmetricState `h` value is used in a BLAKE3 KDF as such:

```rust
fn export_keying_material(h: &[u8; 32], label: &[u8], context: &[u8], output: &mut [u8]) {
  blake3::Hasher::new_derive_key("QUIC Noise_IK_25519_ChaChaPoly_BLAKE3 2024-01-01 23:28:47 export keying material")
    .update(context)
    .update(h)
    .update(label)
    .finalize_xof()
    .fill(output);
}
```

## Header protection

Header protection/obfuscation serves to prevent middle boxes from reading the header. Modification
is not possible since the header is passed as associated data to the cipher. The idea is that if
the header changes in a future quic version, middle boxes may drop the packets because they can't
read the header. But header protection/obfuscation only makes it harder not impossible. Due to
being questionable if it serves it's purpose it was decided that no header obfuscation is applied.

## Retry mechanism

The retry mechanism is identical to what is specified in the quic-tls spec.

## License

MIT OR Apache-2.0
