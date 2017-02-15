# monocypher

Crystal wrapper for a cryptographic library Monocypher (http://loup-vaillant.fr/projects/monocypher/)
For internal use (as this cryptographic library wasn't reviewed yet and so can't be recommended to use), exporting to github to simplify deployment

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

alice_secret = Crypto::SecretKey.new
alice_public = Crypto::PublicKey.new(secret: alice_secret)
bob_secret = Crypto::SecretKey.new
bob_public = Crypto::PublicKey.new(secret: bob_secret)
nonce = Crypto::Nonce.new

message = "This is a test message русский текст"
plaintext = message.bytes
ciphertext = Bytes.new(plaintext.size+Crypto::Header.size+Crypto::Nonce.size)
Crypto.asymmetric_encrypt(your_secret: alice_secret, their_public: bob_public, nonce: nonce, input: plaintext, output: ciphertext)
result = Bytes.new(plaintext.size)
Crypto.asymmetric_decrypt(your_secret: bob_secret, their_public: alice_public, input: ciphertext, output: result)

puts String.new(result)
```
check `spec` dir for more usage examples
