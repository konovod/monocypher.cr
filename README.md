# monocypher

WIP! UPDATING to monocypher 0.5 incomplete

Crystal wrapper for a cryptographic library Monocypher (http://loup-vaillant.fr/projects/monocypher/)

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  monocypher:
    github: konovod/monocypher
```

## Usage

```crystal
require "monocypher"

channel = Channel(Bytes).new

alice_secret = Crypto::SecretKey.new
alice_public = Crypto::PublicKey.new(secret: alice_secret)
bob_secret = Crypto::SecretKey.new
bob_public = Crypto::PublicKey.new(secret: bob_secret)

# alice part
spawn do
  alice_shared = Crypto::SymmetricKey.new(our_secret: alice_secret, their_public: bob_public)
  message = "This is a test message русский текст"
  plaintext = message.to_slice
  ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_SYMMETRIC)
  Crypto.encrypt(key: alice_shared, input: plaintext, output: ciphertext)
  channel.send ciphertext
end

# bob part
bob_shared = Crypto::SymmetricKey.new(our_secret: bob_secret, their_public: alice_public)
ciphertext = channel.receive
result = Bytes.new(ciphertext.size - Crypto::OVERHEAD_SYMMETRIC)
Crypto.decrypt(key: bob_shared, input: ciphertext, output: result)
puts String.new(result)
```
check `spec` dir for more usage examples
