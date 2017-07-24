# monocypher.cr

Crystal wrapper for a cryptographic library Monocypher ([Official site](http://loup-vaillant.fr/projects/monocypher/), [Github page](https://github.com/LoupVaillant/Monocypher))

Sources of Monocypher are included in the shard and will be linked statically with application - this is generally not good for a security-related library, but as Monocypher currently isn't distributed through package manager and crystal applications are distributed mostly in source form, i think this is acceptable as temporary solution.

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
