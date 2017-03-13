require "secure_random"
require "./monocypher/*"

module Crypto
  MUCH_MB = 50

  StaticRecord.declare(SymmetricKey, 32, :random)
  StaticRecord.declare(Salt, 16, :random)
  StaticRecord.declare(Nonce, 24, :random)
  StaticRecord.declare(Header, 16, :zero)
  StaticRecord.declare(SecretKey, 32, :random)
  StaticRecord.declare(PublicKey, 32, :none)
  StaticRecord.declare(PublicSigningKey, 32, :none)
  StaticRecord.declare(Signature, 64, :none)

  struct SecretKey
    def initialize(*, password : String, salt : Salt)
      raise "minimal password length is 4, got#{password.size}" if password.size < 4
      @data = uninitialized UInt8[32]
      area = Pointer(UInt8).malloc(MUCH_MB*1024*1024)
      LibMonoCypher.argon2i(
        @data, 32,
        area, MUCH_MB*1024,
        10,
        password, password.size,
        salt.to_pointer, 16,
        nil, 0,
        nil, 0)
    end
  end

  struct PublicKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonoCypher.x25519_public_key(@data, secret)
    end
  end

  struct PublicSigningKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonoCypher.sign_public_key(@data, secret)
    end
  end

  struct SymmetricKey
    def initialize(*, secret : SecretKey, public : PublicKey)
      @data = uninitialized UInt8[32]
      result = LibMonoCypher.key_exchange(@data, secret, public)
      raise "can't generate public key" unless result == 0
    end
  end

  struct Signature
    def initialize(message, *, secret : SecretKey, public : PublicSigningKey)
      @data = uninitialized UInt8[64]
      LibMonoCypher.sign(@data, secret, public, message, message.size)
    end

    def initialize(message, *, secret : SecretKey)
      @data = uninitialized UInt8[64]
      public = PublicSigningKey.new(secret: secret)
      LibMonoCypher.sign_public_key(public, secret)
      LibMonoCypher.sign(@data, secret, public, message, message.size)
    end

    def check(message, *, public : PublicSigningKey) : Bool
      LibMonoCypher.check(@data, public, message, message.size) == 0
    end
  end

  # adds nonce to the packet
  def self.encrypt(*, output : Bytes, key : SymmetricKey, nonce : Nonce, input : Bytes) : Nil
    raise "data sizes doesn't match" if input.size + OVERHEAD_SYMMETRIC != output.size
    LibMonoCypher.lock(output[Nonce.size, Header.size + input.size], key, nonce, input, input.size)
    output[0, Nonce.size].copy_from(nonce.to_slice)
  end

  def self.decrypt(*, output : Bytes, key : SymmetricKey, input : Bytes) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_SYMMETRIC
    return LibMonoCypher.unlock(output, key, input[0, Nonce.size], input[Nonce.size, Header.size + output.size], output.size + Header.size) == 0
  end

  #  adds additional data to the packet, receiver should know their size
  def self.encrypt(*, output : Bytes, key : SymmetricKey, nonce : Nonce, input : Bytes, additional : Bytes) : Nil
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_SYMMETRIC + additional.size
    LibMonoCypher.aead_lock(
      output[Nonce.size + additional.size, Header.size],
      output[Nonce.size + additional.size + Header.size, input.size],
      key,
      nonce,
      additional, additional.size,
      input, input.size)
    output[0, Nonce.size].copy_from(nonce.to_slice)
    output[Nonce.size, additional.size].copy_from(additional)
  end

  def self.decrypt(*, output : Bytes, additional : Bytes, key : SymmetricKey, input) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_SYMMETRIC + additional.size
    ok = LibMonoCypher.aead_unlock(
      output,
      key,
      input[0, Nonce.size],
      input[Nonce.size + additional.size, Header.size],
      input[Nonce.size, additional.size], additional.size,
      input[Nonce.size + additional.size + Header.size, output.size], output.size) == 0
    additional.copy_from(input[Nonce.size, additional.size]) if ok
    return ok
  end

  # asymmetric scheme: sender pass his public_key as additional data and sign it with shared secret
  # receiver generate shared secret with received key and check all message with it

  # def self.asymmetric_encrypt(*, output : Bytes, our_public: PublicKey, their_public : PublicKey, input)
  #   raise "data sizes doesn't match" if input.size + OVERHEAD_ANONYMOUS != output.size
  #   random_secret = SecretKey.new
  #   LibMonoCypher.anonymous_lock(output, random_secret, their_public, input, input.size)
  # end
  #
  # def self.asymmetric_decrypt(*, output : Bytes, your_secret : SecretKey, input) : PublicKey?
  #   raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_ANONYMOUS
  #
  #   return LibMonoCypher.anonymous_unlock(output, your_secret, input, output.size) == 0
  # end

  OVERHEAD_SYMMETRIC = Header.size + Nonce.size
  # OVERHEAD_ASYMMETRIC = Header.size + Nonce.size
  # OVERHEAD_ANONYMOUS = Header.size + Nonce.size + PublicKey.size
end
