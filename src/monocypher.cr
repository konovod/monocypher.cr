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
      LibMonocypher.argon2i(
        @data, 32,
        area, MUCH_MB*1024,
        10,
        password, password.size,
        salt.to_slice, 16)
    end
  end

  struct PublicKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.x25519_public_key(@data, secret)
    end
  end

  struct PublicSigningKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.sign_public_key(@data, secret)
    end
  end

  struct SymmetricKey
    def initialize(*, our_secret : SecretKey, their_public : PublicKey)
      @data = uninitialized UInt8[32]
      result = LibMonocypher.key_exchange(@data, our_secret, their_public)
      raise "can't generate public key" unless result == 0
    end
  end

  struct Signature
    def initialize(message, *, secret : SecretKey, public : PublicSigningKey)
      @data = uninitialized UInt8[64]
      LibMonocypher.sign(@data, secret, public, message, message.size)
    end

    def initialize(message, *, secret : SecretKey)
      @data = uninitialized UInt8[64]
      public = PublicSigningKey.new(secret: secret)
      LibMonocypher.sign_public_key(public, secret)
      LibMonocypher.sign(@data, secret, public, message, message.size)
    end

    def check(message, *, public : PublicSigningKey) : Bool
      LibMonocypher.check(@data, public, message, message.size) == 0
    end
  end

  # adds nonce and mac to the packet
  def self.encrypt(*, output : Bytes, key : SymmetricKey, input : Bytes, additional : Bytes? = nil) : Nil
    raise "data sizes doesn't match" if output.size != input.size + OVERHEAD_SYMMETRIC
    nonce = Nonce.new
    LibMonocypher.lock_aead(
      output[Nonce.size, Header.size],
      output[Nonce.size + Header.size, input.size],
      key,
      nonce.to_slice,
      additional, additional ? additional.size : 0,
      input, input.size)
    output[0, Nonce.size].copy_from nonce.to_slice
  end

  def self.decrypt(*, output : Bytes, additional : Bytes? = nil, key : SymmetricKey, input : Bytes) : Bool
    raise "data sizes doesn't match" if input.size != output.size + OVERHEAD_SYMMETRIC
    return LibMonocypher.unlock_aead(
      output,
      key,
      input[0, Nonce.size],
      input[Nonce.size, Header.size],
      additional, additional ? additional.size : 0,
      input[Nonce.size + Header.size, output.size], output.size) == 0
  end

  OVERHEAD_SYMMETRIC = Header.size + Nonce.size
end
