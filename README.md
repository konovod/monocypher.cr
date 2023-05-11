# monocypher.cr

[![Linux CI](https://github.com/konovod/monocypher.cr/actions/workflows/linux-ci.yml/badge.svg)](https://github.com/konovod/monocypher.cr/actions/workflows/linux-ci.yml)
[![MacOSX CI](https://github.com/konovod/monocypher.cr/actions/workflows/macos-ci.yml/badge.svg)](https://github.com/konovod/monocypher.cr/actions/workflows/macos-ci.yml)
[![Windows CI](https://github.com/konovod/monocypher.cr/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/konovod/monocypher.cr/actions/workflows/windows-ci.yml)

Crystal wrapper for a cryptographic library Monocypher ([Official site](https://monocypher.org), [Github page](https://github.com/LoupVaillant/Monocypher))

Note: Sources of Monocypher (version 4.0.1 currently) are included in the shard and will be linked statically with application.
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

    2.1. On Windows: 
  currently, shards way isn't supported, but you can compile monocypher manually using following commands(from visual studio development prompt):
    ```
    cd ext
    cl /c /EHsc /O2 /MT monocypher.c 
    cl /c /EHsc /O2 /MT monocypher-ed25519.c
    lib monocypher.obj monocypher-ed25519.obj
    ```    
    and then copy `monocypher.lib` file to where your Crystal looks for lib files.

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
  alice_shared = Crypto::SymmetricKey.new(secret1: alice_secret, public2: bob_public)
  message = "This is a test message русский текст"
  plaintext = message.to_slice
  ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_SYMMETRIC)
  Crypto.encrypt(key: alice_shared, input: plaintext, output: ciphertext)
  channel.send ciphertext
end

# receiver part
bob_shared = Crypto::SymmetricKey.new(secret2: bob_secret, public1: alice_public)
ciphertext = channel.receive
result = Bytes.new(ciphertext.size - Crypto::OVERHEAD_SYMMETRIC)
Crypto.decrypt(key: bob_shared, input: ciphertext, output: result)
puts String.new(result)
```

check `spec` dir for more usage examples (TODO - other examples)

## Hashes
Monocypher includes functions for cryptographic hashes BLAKE2b and SHA-512, they are wrapped with simple crystal functions
```crystal
Crypto.sha512("".to_slice).hexstring
# "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

Crypto.blake2b("abc".to_slice, key: "".to_slice, hash_size: 64).hexstring
# same as Crypto.blake2b("abc".to_slice).hexstring
# ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923
```
There is also `Digest` interface used in Crystal stdlib:
```
  digest = Crypto::Digest::SHA512.new
  digest << "123"
  digest.final.hexstring  # "3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"

  digest = Crypto::Digest::BLAKE2b.new(key: "".to_slice, hash_size: 64)
  digest << "123"
  digest.final.hexstring  # "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
```

## Development status
Lowlevel wrapper currently covers all of Monocypher 4.0.1 release and can be called directly.

Highlevel wrapper status:

|Area | Status | Comment |
|-----|--------|---------|
| Constant Time Comparison | Not planned | Already in stdlib: see https://crystal-lang.org/api/1.7.2/Crypto/Subtle.html |
| Memory Wipe | Done |  |
| Authenticated Encryption | Partially done | TODO - streaming interface |
| Blake2b Hash | Done |  |
| SHA-512 hash | Partially done | TODO - hmac and hkdf modes |
| Password Key Derivation | Partially done | TODO - expose additional options in high-level interface |
| X25519 Key Exchange | Partially done | TODO - Generating pair |
| Public Key Signatures | Partially done | TODO - XEdDSA implementation |
| Ed25519 | Done |  |
| ChaCha20 | - | Is high-level wrapper needed? |
| Poly1305 | - | Is high-level wrapper needed? |
| Elligator | - | Is high-level wrapper needed? |

Other planned features:
 - [ ] Inline docs for everything
 - [ ] Input size checking everywhere