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

  struct SecretKey
    def initialize(*, password : String, salt : Salt)
      @data = uninitialized UInt8[32]
      area = Pointer(UInt8).malloc(MUCH_MB*1024*1024)
      LibMonoCypher.argon2i(@data, 32, password, password.size, salt.to_pointer, 16, nil, 0, nil, 0, area, MUCH_MB*1024, 10)
    end
  end

  struct PublicKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonoCypher.x25519_public_key(@data, secret)
    end
  end

  def self.symmetric_encrypt(*, output : Bytes, key : SymmetricKey, nonce : Nonce, input)
    raise "data sizes doesn't match" if input.size + OVERHEAD_SYMMETRIC != output.size
    LibMonoCypher.ae_lock(output[Nonce.size, Header.size + input.size], key, nonce, input, input.size)
    output[0, Nonce.size].copy_from(nonce.to_slice)
  end

  def self.symmetric_decrypt(*, output : Bytes, key : SymmetricKey, input) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_SYMMETRIC
    nonce = Nonce.new
    nonce.to_slice.copy_from(input[0, Nonce.size])
    return LibMonoCypher.ae_unlock(output, key, nonce, input[Nonce.size, Header.size + output.size], output.size) == 0
  end

  def self.asymmetric_encrypt(*, output : Bytes, your_secret : SecretKey, their_public : PublicKey, nonce : Nonce, input)
    raise "data sizes doesn't match" if input.size + OVERHEAD_ASYMMETRIC != output.size
    LibMonoCypher.lock(output[Nonce.size, Header.size + input.size], your_secret, their_public, nonce, input, input.size)
    output[0, Nonce.size].copy_from(nonce.to_slice)
  end

  def self.asymmetric_decrypt(*, output : Bytes, your_secret : SecretKey, their_public : PublicKey, input) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_ASYMMETRIC
    nonce = Nonce.new
    nonce.to_slice.copy_from(input[0, Nonce.size])
    return LibMonoCypher.unlock(output, your_secret, their_public, nonce, input[Nonce.size, Header.size + output.size], output.size) == 0
  end

  def self.asymmetric_encrypt(*, output : Bytes, their_public : PublicKey, input)
    raise "data sizes doesn't match" if input.size + OVERHEAD_ANONYMOUS != output.size
    random_secret = SecretKey.new
    LibMonoCypher.anonymous_lock(output, random_secret, their_public, input, input.size)
  end

  def self.asymmetric_decrypt(*, output : Bytes, your_secret : SecretKey, input) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_ANONYMOUS
    return LibMonoCypher.anonymous_unlock(output, your_secret, input, output.size) == 0
  end

  OVERHEAD_SYMMETRIC  = Header.size + Nonce.size
  OVERHEAD_ASYMMETRIC = Header.size + Nonce.size
  OVERHEAD_ANONYMOUS  = Header.size + SecretKey.size
end
