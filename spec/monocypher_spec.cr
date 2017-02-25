require "./spec_helper"

describe Crypto do
  it "compare buffers" do
    salt1 = Crypto::Salt.new
    salt2 = salt1
    salt3 = Crypto::Salt.new
    nonce = Crypto::Nonce.new
    salt1.compare(salt2).should be_true
    salt1.compare(salt3).should be_false
    salt1.compare(nonce).should be_false
  end

  it "hashes password" do
    pass = "12345678"
    salt = Crypto::Salt.new
    key1 = Crypto::SecretKey.new(password: pass, salt: salt)
    key2 = Crypto::SecretKey.new(password: "12345678", salt: salt)
    key3 = Crypto::SecretKey.new(password: "12345678z", salt: salt)
    key1.should eq key2
    key1.should_not eq key3
  end

  it "generate public keys" do
    secret1 = Crypto::SecretKey.new
    secret2 = Crypto::SecretKey.new
    public1 = Crypto::PublicKey.new(secret: secret1)
    public2 = Crypto::PublicKey.new(secret: secret2)
    public11 = Crypto::PublicKey.new(secret: secret1)
    public1.should eq public11
    public1.should_not eq public2
    public1.should_not eq secret1
  end

  it "read keys from string" do
    secret = Crypto::SecretKey.new("5f5ade01649f59af5de9310fb967966e5c4715fff4ed8c41cd229a618f268872")
    public = Crypto::PublicKey.new("f239af4eaf613180def4bef6b0e80a8f7c7506e8a3722d1b1a04239812221704")
    public.should eq Crypto::PublicKey.new(secret: secret)
    wrong = Crypto::PublicKey.new("f239af4eaf613180def4bef6b0e80a8f7c7506e8a3722d1b1a04239812221714")
    wrong.should_not eq Crypto::PublicKey.new(secret: secret)
    expect_raises(Exception) do
      Crypto::PublicKey.new("f239af4eaf6_13180def4bef6b0e80a8f7c7506e8a3722d1b1a0423981222171")
    end
    expect_raises(Exception) do
      Crypto::PublicKey.new("f239af4eaf6")
    end
  end

  it "does symmetric cryptography" do
    key = Crypto::SymmetricKey.new
    nonce = Crypto::Nonce.new
    message = "This is a test message русский текст"
    plaintext = message.bytes
    ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_SYMMETRIC)
    Crypto.symmetric_encrypt(key: key, nonce: nonce, input: plaintext, output: ciphertext)
    result = Bytes.new(plaintext.size)
    Crypto.symmetric_decrypt(key: key, input: ciphertext, output: result).should be_true
    String.new(result).should eq message

    ciphertext.to_unsafe[0] += 1
    Crypto.symmetric_decrypt(key: key, input: ciphertext, output: result).should be_false
  end

  it "does asymmetric cryptography" do
    alice_secret = Crypto::SecretKey.new
    alice_public = Crypto::PublicKey.new(secret: alice_secret)
    bob_secret = Crypto::SecretKey.new
    bob_public = Crypto::PublicKey.new(secret: bob_secret)
    nonce = Crypto::Nonce.new

    message = "This is a test message русский текст"
    plaintext = message.bytes
    ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_ASYMMETRIC)
    Crypto.asymmetric_encrypt(your_secret: alice_secret, their_public: bob_public, nonce: nonce, input: plaintext, output: ciphertext)
    result = Bytes.new(plaintext.size)
    Crypto.asymmetric_decrypt(your_secret: bob_secret, their_public: alice_public, input: ciphertext, output: result).should be_true
    String.new(result).should eq message

    ciphertext.to_unsafe[13] += 1
    Crypto.asymmetric_decrypt(your_secret: bob_secret, their_public: alice_public, input: ciphertext, output: result).should be_false
  end

  it "does one pair asymmetric cryptography" do
    bob_secret = Crypto::SecretKey.new
    bob_public = Crypto::PublicKey.new(secret: bob_secret)

    message = "This is a test message русский текст"
    plaintext = message.bytes
    ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_ANONYMOUS)
    Crypto.asymmetric_encrypt(their_public: bob_public, input: plaintext, output: ciphertext)
    result = Bytes.new(plaintext.size)
    Crypto.asymmetric_decrypt(your_secret: bob_secret, input: ciphertext, output: result).should be_true
    String.new(result).should eq message

    ciphertext.to_unsafe[29] += 1
    Crypto.asymmetric_decrypt(your_secret: bob_secret, input: ciphertext, output: result).should be_false
  end

  it "rerolls random keys to avoid reallocation" do
    nonce = Crypto::Nonce.new
    nonce2 = nonce
    nonce2.compare(nonce).should be_true
    nonce2.reroll
    nonce2.compare(nonce).should be_false
    nonce.reroll
    nonce2.compare(nonce).should be_false
  end
end
