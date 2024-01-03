# Noise for the quinn quic implementation

This is a fork of the `ipfs-rust/quinn-noise` project. It is a significant rewrite and is not compatible.

## Handshake pattern

`Noise_IK_{DH}_{Cipher}_{Hash}`.

My intended usecase is similar to that of wireguard or SSH. The client will know the server's public key,
but the server will not know which client to initially expect. Because of this, I am using the `IK` pattern

- `I` - Static key for initiator Immediately transmitted to responder, despite reduced or absent identity hiding
- `K` - Static key for responder Known to initiator

```
IK:
    <- s
    ...
    -> e, es, s, ss  || client transport parameters || 0rtt-data
    <- e, ee, se     || server transport parameters || 1rtt-data
```

## QUIC version

Because this is not 1 protocol, but many, I will not provide a QUIC version to use.
See <https://github.com/quicwg/base-drafts/wiki/QUIC-Versions> for version information.

## Export Keying Material

The final SymmetricState `h` value is used as the input keying material to a HKDF.

```
out = hkdf_expand(h, label || context, out.len())
```

## Header protection

Header protection/obfuscation serves to prevent middle boxes from reading the header. Modification
is not possible since the header is passed as associated data to the cipher. The idea is that if
the header changes in a future quic version, middle boxes may drop the packets because they can't
read the header. But header protection/obfuscation only makes it harder not impossible. Due to
being questionable if it serves it's purpose it was decided that no header obfuscation is applied.

## Retry mechanism

The retry mechanism is similar to what is specified in the [quic-tls](https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity) spec.

The Retry Integrity Tag is a 128-bit field that is computed as the output of HMAC (using the provided hash function) used with the following inputs:

- The secret key, K, is equal to `hkdf_expand(0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e, "QUIC integrity key" || handshake_pattern, hash_output_size)`.
- The associated data, A, is the contents of the Retry Pseudo-Packet, as illustrated in Figure 8

## License

MIT OR Apache-2.0
