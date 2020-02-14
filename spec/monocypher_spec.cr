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
    expect_raises(Exception) do
      Crypto::PublicKey.new("f239af4eaf613180def4bef6b0e80a8f7c7506e8a3722d1b1a0423981222171400")
    end
  end

  it "generate shared secret" do
    secret1 = Crypto::SecretKey.new
    secret2 = Crypto::SecretKey.new
    public1 = Crypto::PublicKey.new(secret: secret1)
    public2 = Crypto::PublicKey.new(secret: secret2)

    shared1 = Crypto::SymmetricKey.new(our_secret: secret1, their_public: public2)
    shared2 = Crypto::SymmetricKey.new(our_secret: secret2, their_public: public1)
    shared3 = Crypto::SymmetricKey.new(our_secret: secret1, their_public: public1)

    shared1.should eq shared2
    shared1.should_not eq shared3
  end

  it "sign messages" do
    secret1 = Crypto::SecretKey.new
    public1 = Crypto::PublicSigningKey.new(secret: secret1)
    secret2 = Crypto::SecretKey.new
    public2 = Crypto::PublicSigningKey.new(secret: secret2)

    message = "12345678"
    signature1 = Crypto::Signature.new(message, secret: secret1, public: public1)
    signature11 = Crypto::Signature.new(message, secret: secret1)
    signature2 = Crypto::Signature.new(message, secret: secret2, public: public1)

    signature1.should eq signature11
    signature1.check("12345678", public: public1).should be_true
    signature1.check("123456789", public: public1).should be_false
    signature2.check("12345678", public: public1).should be_false
  end

  it "does symmetric cryptography" do
    key = Crypto::SymmetricKey.new
    message = "This is a test message русский текст"
    plaintext = message.to_slice
    ciphertext = Bytes.new(plaintext.size + Crypto::OVERHEAD_SYMMETRIC)
    Crypto.encrypt(key: key, input: plaintext, output: ciphertext)
    result = Bytes.new(plaintext.size)
    Crypto.decrypt(key: key, input: ciphertext, output: result).should be_true
    String.new(result).should eq message

    ciphertext.to_unsafe[0] += 1
    Crypto.decrypt(key: key, input: ciphertext, output: result).should be_false
  end

  it "does symmetric cryptography with additional data" do
    key = Crypto::SymmetricKey.new
    message = "This is a test message русский текст".to_slice
    additional = "Some additional data дополнительные данные".to_slice
    ciphertext = Bytes.new(message.size + Crypto::OVERHEAD_SYMMETRIC)
    Crypto.encrypt(key: key, input: message, output: ciphertext, additional: additional)

    result = Bytes.new(message.size)
    Crypto.decrypt(key: key, input: ciphertext, output: result, additional: additional).should be_true
    result.should eq message

    wrong = "wrong additional data".to_slice
    Crypto.decrypt(key: key, input: ciphertext, output: result, additional: wrong).should be_false
  end

  it "complex schemes can be implemented" do
    server_secret = Crypto::SecretKey.new
    server_public = Crypto::PublicKey.new(secret: server_secret)

    channel = Channel(Bytes).new # of cource should be fixed size in real apps

    # client pass its public key as additional data
    spawn do
      client_secret = Crypto::SecretKey.new
      client_public = Crypto::PublicKey.new(secret: client_secret)
      client_shared = Crypto::SymmetricKey.new(our_secret: client_secret, their_public: server_public)
      message = "my_login".to_slice
      ciphertext = Bytes.new(message.size + Crypto::OVERHEAD_SYMMETRIC)
      add_data = client_public.to_slice
      Crypto.encrypt(key: client_shared, input: message, output: ciphertext, additional: add_data)

      channel.send ciphertext
      channel.send add_data

      response = channel.receive
      decoded = Bytes.new(response.size - Crypto::OVERHEAD_SYMMETRIC)
      Crypto.decrypt(key: client_shared, input: response, output: decoded)
      String.new(decoded).should eq "Hello, my_login"
    end

    # server receives key and answers to client
    spawn do
      ciphertext = channel.receive
      req_key = channel.receive
      server_shared = Crypto::SymmetricKey.new(
        our_secret: server_secret,
        their_public: Crypto::PublicKey.from_bytes(req_key))
      request_decoded = Bytes.new(ciphertext.size - Crypto::OVERHEAD_SYMMETRIC)
      Crypto.decrypt(key: server_shared, input: ciphertext, output: request_decoded, additional: req_key)
      String.new(request_decoded).should eq "my_login"
      answer = "Hello, my_login".to_slice
      ciphertext = Bytes.new(answer.size + Crypto::OVERHEAD_SYMMETRIC)
      Crypto.encrypt(key: server_shared, input: answer, output: ciphertext)
      channel.send ciphertext
    end
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
