require "./monocypher/*"

module Crypto
  MUCH_MB = 50

  StaticRecord.declare(SymmetricKey, 32, :random)
  StaticRecord.declare(Salt, 16, :random)
  StaticRecord.declare(Nonce, 24, :random)
  StaticRecord.declare(MAC, 16, :zero)
  StaticRecord.declare(SecretKey, 32, :random)
  StaticRecord.declare(PublicKey, 32, :none)

  StaticRecord.declare(SecretSigningKey, 64, :none)
  StaticRecord.declare(PublicSigningKey, 32, :none)
  StaticRecord.declare(Signature, 64, :none)

  StaticRecord.declare(Ed25519SecretSigningKey, 64, :none)
  StaticRecord.declare(Ed25519PublicSigningKey, 32, :none)
  StaticRecord.declare(Ed25519Signature, 64, :none)

  struct SecretKey
    def initialize(*, password : String, salt : Salt)
      raise "minimal password length is 4, got#{password.bytesize}" if password.bytesize < 4
      @data = uninitialized UInt8[32]
      area = Pointer(UInt8).malloc(MUCH_MB*1024*1024)
      LibMonocypher.argon2(
        @data, 32,
        area,
        LibMonocypher::Argon2Config.new(algorithm: LibMonocypher::Argon2Algorithm::I, nb_blocks: MUCH_MB*1024, nb_passes: 3, nb_lanes: 1),
        LibMonocypher::Argon2Inputs.new(pass: password, pass_size: password.bytesize, salt: salt.to_slice, salt_size: 16),
        LibMonocypher::Argon2Extras.new(key: nil, ad: nil, key_size: 0, ad_size: 0)
      )
    end
  end

  struct PublicKey
    def initialize(*, secret : SecretKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.x25519_public_key(@data, secret)
    end

    def initialize(*, public_signing : PublicSigningKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.eddsa_to_x25519(@data, public)
    end
  end

  struct SymmetricKey
    def initialize(*, secret1 : SecretKey, public1 : PublicKey, public2 : PublicKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.x25519(@data, secret1, public2)
      ctx = LibMonocypher::BLAKE2bCtx.new
      LibMonocypher.blake2b_init(pointerof(ctx), 32)
      LibMonocypher.blake2b_update(pointerof(ctx), @data, 32)
      LibMonocypher.blake2b_update(pointerof(ctx), public1.to_slice, 32)
      LibMonocypher.blake2b_update(pointerof(ctx), public2.to_slice, 32)
      LibMonocypher.blake2b_final(pointerof(ctx), @data)
    end

    def initialize(*, secret2 : SecretKey, public1 : PublicKey, public2 : PublicKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.x25519(@data, secret2, public1)
      ctx = LibMonocypher::BLAKE2bCtx.new
      LibMonocypher.blake2b_init(pointerof(ctx), 32)
      LibMonocypher.blake2b_update(pointerof(ctx), @data, 32)
      LibMonocypher.blake2b_update(pointerof(ctx), public1.to_slice, 32)
      LibMonocypher.blake2b_update(pointerof(ctx), public2.to_slice, 32)
      LibMonocypher.blake2b_final(pointerof(ctx), @data)
    end

    def self.new(*, secret1 : SecretKey, public2 : PublicKey)
      new(secret1: secret1, public1: PublicKey.new(secret: secret1), public2: public2)
    end

    def self.new(*, secret2 : SecretKey, public1 : PublicKey)
      new(secret2: secret2, public2: PublicKey.new(secret: secret2), public1: public1)
    end

    # TODO - create_pair
    # def self.create_pair(our_secret : SecretKey, our_public : PublicKey, their_public : PublicKey)
    #   adata = Bytes.new(64)
    #   LibMonocypher.x25519(@data, our_secret, their_public)
    #   ctx = LibMonocypher::BLAKE2bCtx.new
    #   LibMonocypher.blake2b_init(pointerof(ctx), 64)
    #   LibMonocypher.blake2b_update(pointerof(ctx), @data, 32)
    #   LibMonocypher.blake2b_update(pointerof(ctx), our_public.to_slice, 32)
    #   LibMonocypher.blake2b_update(pointerof(ctx), their_public.to_slice, 32)
    #   LibMonocypher.blake2b_final(pointerof(ctx), @data)
    #   key1 = SymmetricKey.from_bytes(adata[0, 32])
    #   key2 = SymmetricKey.from_bytes(adata[32, 32])
    #   return key1, key2
    # end
  end

  struct PublicSigningKey
    def initialize(*, public : PublicKey)
      @data = uninitialized UInt8[32]
      LibMonocypher.x25519_to_eddsa(@data, public)
    end
  end

  def self.generate_signing_keys : Tuple(SecretSigningKey, PublicSigningKey)
    secret_bytes = uninitialized UInt8[64]
    public_bytes = uninitialized UInt8[32]
    seed = uninitialized UInt8[32]
    Random::Secure.random_bytes(seed.to_slice)
    LibMonocypher.eddsa_key_pair(secret_bytes, public_bytes, seed)
    secret = SecretSigningKey.from_bytes(secret_bytes.to_slice)
    public = PublicSigningKey.from_bytes(public_bytes.to_slice)
    return secret, public
  end

  struct Signature
    def initialize(message : Bytes, *, secret : SecretSigningKey)
      @data = uninitialized UInt8[64]
      LibMonocypher.eddsa_sign(@data, secret, message, message.size)
    end

    def check(message : Bytes, *, public : PublicSigningKey) : Bool
      LibMonocypher.eddsa_check(@data, public, message, message.size) == 0
    end
  end

  def self.generate_ed25519_keys : Tuple(Ed25519SecretSigningKey, Ed25519PublicSigningKey)
    secret_bytes = uninitialized UInt8[64]
    public_bytes = uninitialized UInt8[32]
    seed = uninitialized UInt8[32]
    Random::Secure.random_bytes(seed.to_slice)
    LibMonocypher.ed25519_key_pair(secret_bytes, public_bytes, seed)
    secret = Ed25519SecretSigningKey.from_bytes(secret_bytes.to_slice)
    public = Ed25519PublicSigningKey.from_bytes(public_bytes.to_slice)
    return secret, public
  end

  struct Ed25519Signature
    def initialize(message : Bytes, *, secret : Ed25519SecretSigningKey)
      @data = uninitialized UInt8[64]
      LibMonocypher.ed25519_sign(@data, secret, message, message.size)
    end

    def initialize(*, message_hash : Bytes, secret : Ed25519SecretSigningKey)
      raise "size of message_hash must be 64 (received #{message_hash.size})" unless message_hash.size == 64
      @data = uninitialized UInt8[64]
      LibMonocypher.ed25519_ph_sign(@data, secret, hash)
    end

    def check(message : Bytes, *, public : Ed25519PublicSigningKey) : Bool
      LibMonocypher.ed25519_check(@data, public, message, message.size) == 0
    end

    def check(*, message_hash : Bytes, public : Ed25519PublicSigningKey) : Bool
      raise "size of message_hash must be 64 (received #{message_hash.size})" unless message_hash.size == 64
      LibMonocypher.ed25519_ph_check(@data, public, message_hash) == 0
    end
  end

  # adds nonce and mac to the packet
  def self.encrypt(*, output : Bytes, key : SymmetricKey, input : Bytes, additional : Bytes? = nil) : Nil
    raise "data sizes doesn't match" if output.size != input.size + OVERHEAD_SYMMETRIC
    nonce = Nonce.new
    text_size = input.size
    LibMonocypher.aead_lock(
      output[Nonce.size, text_size],                # cipher_text
      output[Nonce.size + text_size, MAC.size],     # mac
      key,                                          # key
      nonce.to_slice,                               # nonce
      additional, additional ? additional.size : 0, # ad, ad_size
      input,                                        # plain_text
      text_size    )                                # text_size
    output[0, Nonce.size].copy_from nonce.to_slice
  end

  def self.decrypt(*, output : Bytes, additional : Bytes? = nil, key : SymmetricKey, input : Bytes) : Bool
    text_size = output.size
    raise "data sizes doesn't match" if input.size != text_size + OVERHEAD_SYMMETRIC
    LibMonocypher.aead_unlock(
      output,                                       # plain_text
      input[Nonce.size + text_size, MAC.size],      # mac
      key,                                          # key
      input[0, Nonce.size],                         # nonce
      additional, additional ? additional.size : 0, # ad, ad_size
      input[Nonce.size, text_size],                 # cipher_text
      output.size                                   # text_size
    ) == 0
  end

  OVERHEAD_SYMMETRIC = MAC.size + Nonce.size
end
