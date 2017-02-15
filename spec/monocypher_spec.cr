require "./spec_helper"

describe Crypto do

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

  it "does symmetric cryptography" do
    key = Crypto::SymmetricKey.new
    nonce = Crypto::Nonce.new
    message = "This is a test message русский текст"
    plaintext = message.bytes
    ciphertext = Bytes.new(plaintext.size+Crypto::Header.size+Crypto::Nonce.size)
    Crypto.symmetric_encrypt(key: key, nonce: nonce, input: plaintext, output: ciphertext)
    result = Bytes.new(plaintext.size)
    Crypto.symmetric_decrypt(key: key, input: ciphertext, output: result).should be_true
    String.new(result).should eq message
  end



end
