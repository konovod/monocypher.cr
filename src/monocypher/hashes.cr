require "./libmonocypher"
require "digest/digest"

module Crypto
  # Calculate SHA-512 hash of `data`
  def self.sha512(data : Bytes) : Bytes
    Bytes.new(512 // 8).tap do |result|
      LibMonocypher.sha512(result, data, data.size)
    end
  end

  # Calculate HMAC with SHA-512, that can be used for message authentication codes or as a random oracle.
  def self.sha512_hmac(data : Bytes, key : Bytes) : Bytes
    raise ArgumentError.new("key must not be empty") if key.size == 0
    Bytes.new(512 // 8).tap do |result|
      LibMonocypher.sha512_hmac(result, key, key.size, data, data.size)
    end
  end

  # Calculate BLAKE2b hash of `data`, result will have `hash_size` bytes.
  #
  # `hash_size` - Length of hash, in bytes. Must be between 1 and 64. Anything below 16 is discouraged when using BLAKE2b as a message authentication code.
  # Anything below 32 is discouraged when using BLAKE2b as a key derivation function (KDF).
  #
  # `key` - Some secret key. When uniformly random, one cannot predict the final hash without it.
  def self.blake2b(data : Bytes, *, hash_size : Int32 = 64, key : Bytes? = nil) : Bytes
    Bytes.new(hash_size).tap do |result|
      if key
        LibMonocypher.blake2b_keyed(result, hash_size, key, key.size, data, data.size)
      else
        LibMonocypher.blake2b(result, hash_size, data, data.size)
      end
    end
  end

  module Digest
    # SHA-512, a cryptographically secure hash
    #
    # See [Crystal API docs](https://crystal-lang.org/api/latest/Digest.html) for details on how to use `Digest` interface
    class SHA512 < ::Digest
      @ctx = LibMonocypher::Sha512Ctx.new

      def initialize
        reset_impl
      end

      # Hashes data incrementally.
      def update_impl(data : Bytes) : Nil
        LibMonocypher.sha512_update(pointerof(@ctx), data, data.size)
      end

      # Stores the output digest of #digest_size bytes in dst.
      def final_impl(dst : Bytes) : Nil
        LibMonocypher.sha512_final(pointerof(@ctx), dst)
      end

      # Resets the object to it's initial state.
      def reset_impl : Nil
        LibMonocypher.sha512_init(pointerof(@ctx))
      end

      # Returns the digest output size in bytes.
      def digest_size : Int32
        64
      end
    end

    # Implement HMAC with SHA-512, and can be used for message authentication codes or as a random oracle.
    #
    # See [Crystal API docs](https://crystal-lang.org/api/latest/Digest.html) for details on how to use `Digest` interface
    class SHA512HMAC < ::Digest
      @ctx = LibMonocypher::Sha512HmacCtx.new

      def initialize(@key : Bytes)
        raise ArgumentError.new("key must not be empty") if key.size == 0
        reset_impl
      end

      # Hashes data incrementally.
      def update_impl(data : Bytes) : Nil
        LibMonocypher.sha512_hmac_update(pointerof(@ctx), data, data.size)
      end

      # Stores the output digest of #digest_size bytes in dst.
      def final_impl(dst : Bytes) : Nil
        LibMonocypher.sha512_hmac_final(pointerof(@ctx), dst)
      end

      # Resets the object to it's initial state.
      def reset_impl : Nil
        LibMonocypher.sha512_hmac_init(pointerof(@ctx), @key, @key.size)
      end

      # Returns the digest output size in bytes.
      def digest_size : Int32
        64
      end
    end

    # BLAKE2b, a cryptographically secure hash based on the ideas of ChaCha20.
    #
    # See [Crystal API docs](https://crystal-lang.org/api/latest/Digest.html) for details on how to use `Digest` interface
    class BLAKE2b < ::Digest
      @ctx = LibMonocypher::BLAKE2bCtx.new

      # Initializes Digest with given parameters
      #
      # `hash_size` - Length of hash, in bytes. Must be between 1 and 64. Anything below 32 is discouraged when using BLAKE2b as a general-purpose hash function.
      # `key` - Some secret key. When uniformly random, one cannot predict the final hash without it.
      def initialize(@hash_size = 64, @key : Bytes? = nil)
        raise ArgumentError.new("hash_size must be between 1 and 64, received #{@hash_size}") unless (1..64).includes? @hash_size
        if key = @key
          raise ArgumentError.new("key.size must be between 0 and 64, received #{key.size}") unless (0..64).includes? key.size
        end
        reset_impl
      end

      # Hashes data incrementally.
      def update_impl(data : Bytes) : Nil
        LibMonocypher.blake2b_update(pointerof(@ctx), data, data.size)
      end

      # Stores the output digest of #digest_size bytes in dst.
      def final_impl(dst : Bytes) : Nil
        LibMonocypher.blake2b_final(pointerof(@ctx), dst)
      end

      # Resets the object to it's initial state.
      def reset_impl : Nil
        if key = @key
          LibMonocypher.blake2b_keyed_init(pointerof(@ctx), @hash_size, key, key.size)
        else
          LibMonocypher.blake2b_init(pointerof(@ctx), @hash_size)
        end
      end

      # Returns the digest output size in bytes.
      def digest_size : Int32
        @hash_size
      end
    end
  end
end
