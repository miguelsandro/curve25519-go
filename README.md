Axlsign
=======

Ed25519-like signatures with X25519 keys, Axolotl-style.

## Functions

Functions accept and return `[]uint8 Array`s.

### generateKeyPair(seed) -> keyPair

Generates a new key pair from the given 32-byte secret seed (which should be
generated with a CSPRNG) and returns it as object:

```
keyPair = {
    privateKey: IntArray // 32-byte private key
    publicKey: IntArray  // 32-byte public key
}
```

The returned keys can be used for signing and key agreement.

### sign(privateKey, message, [random]) -> signature

Signs the given message using the private key and returns signature.

Optional random data argument (which must have 64 random bytes) turns on
hash separation and randomization to make signatures non-deterministic.

### verify(publicKey, message, signature) -> 1 | 0

Verifies the given signature for the message using the given private key.
Returns `1` if the signature is valid, `0` otherwise.

### signMessage(privateKey, message, [random]) -> signedMessage

Signs the given message using the private key and returns
a signed message (signature concatenated with the message copy).

Optional random data argument (which must have 64 random bytes) turns on
hash separation and randomization to make signatures non-deterministic.

### openMessage(publicKey, signedMessage) -> message | null

Verifies signed message with the public key and returns the original message
without signature if it's correct or `nil` if verification fails.

### sharedKey(privateKey, publicKey) -> rawSharedKey

Returns a raw shared key between own private key and peer's public key (in
other words, this is an ECC Diffie-Hellman function X25519, performing
scalar multiplication).

## Credits

Ported to Go (https://golang.org/) by Miguel Lucero <miguel.sandro@gmail.com> nov 2017.
You can use it under MIT or CC0 license.

Curve25519 signatures idea and math by Trevor Perrin
<https://moderncrypto.org/mail-archive/curves/2014/000205.html>

Derived from axlsign.js written by Dmitry Chestnykh. 
<https://github.com/wavesplatform/curve25519-js>
