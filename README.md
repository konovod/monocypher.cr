# monocypher.cr

[![Linux CI](https://github.com/Axentro/monocypher.cr/actions/workflows/linux-ci.yml/badge.svg)](https://github.com/Axentro/monocypher.cr/actions/workflows/linux-ci.yml)

Crystal wrapper for a cryptographic library Monocypher ([Official site](https://monocypher.org), [Github page](https://github.com/LoupVaillant/Monocypher))

Note: Sources of Monocypher (version 3.1.2 currently) are included in the shard and will be linked statically with application.
On the other hand, if libmonocypher.so is present in library paths at the time of compilation, linker seems to prefer dynamic linking.

Also included is the standard ED25519 cryptography which Monocypher supplies as an optional component.

## Installation

1. Add this to your application's `shard.yml`:

```yaml
dependencies:
  monocypher:
    github: konovod/monocypher
```

2. `shards update` will install a shard and compile Monocypher static library. So you need clang or gcc.

## Usage

1. The wrapper is created with an additional requirement - using a crypto library for encrypting/decrypting of messages shouldn't cause heap allocations.
So it doesn't provide function `plaintext = Crypto.unlock(ciphertext, key)` (as it will require allocation of `plaintext` every time message being decrypted). Instead it provide `Crypto.decrypt(key: Bytes, input: Bytes, output: Bytes)` function that will operate on preallocated buffers.
2. Most functions receive named arguments. This makes code slightly more verbose, but hopefully will prevent messing up arguments order.

Example of usage:

```crystal
require "monocypher"

channel = Channel(Bytes).new # should be fixed size in real apps

alice_secret = Crypto::SecretKey.new
alice_public = Crypto::PublicKey.new(secret: alice_secret)
bob_secret = Crypto::SecretKey.new
bob_public = Crypto::PublicKey.new(secret: bob_secret)

# sender part
spawn do
  alice_shared = Crypto::SymmetricKey.new(our_secret: alice_secret, their_public: bob_public)
  message = "This is a test message русский текст"
  plaintext = message.to_slice
  ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_SYMMETRIC)
  Crypto.encrypt(key: alice_shared, input: plaintext, output: ciphertext)
  channel.send ciphertext
end

# receiver part
bob_shared = Crypto::SymmetricKey.new(our_secret: bob_secret, their_public: alice_public)
ciphertext = channel.receive
result = Bytes.new(ciphertext.size - Crypto::OVERHEAD_SYMMETRIC)
Crypto.decrypt(key: bob_shared, input: ciphertext, output: result)
puts String.new(result)
```

check `spec` dir for more usage examples (TODO - other examples)

## Hashes
Monocypher includes functions for cryptographic hashes Blake2b and SHA-512, they are wrapped with simple crystal functions (TODO - API for incremental hashing. How it should looks?)
```crystal
Crypto.sha512("".to_slice).hexstring
# "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

Crypto.blake2b("abc".to_slice, key: "".to_slice, hash_size: 64).hexstring
# same as Crypto.blake2b("abc".to_slice).hexstring
# ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
```
