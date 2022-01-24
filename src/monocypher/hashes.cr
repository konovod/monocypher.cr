require "./libmonocypher"
require "digest/digest"

module Crypto
  def self.sha512(data : Bytes) : Bytes
    Bytes.new(512 // 8).tap do |result|
      LibMonocypher.sha512(result, data, data.size)
    end
  end

  def self.blake2b(data : Bytes, *, hash_size : Int32 = 64, key : Bytes? = nil) : Bytes
    Bytes.new(hash_size).tap do |result|
      if key
        LibMonocypher.blake2b_general(result, hash_size, key, key.size, data, data.size)
      else
        LibMonocypher.blake2b_general(result, hash_size, nil, 0, data, data.size)
      end
    end
  end

  module Digest
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

    class Blake2b < ::Digest
      @ctx = LibMonocypher::Blake2bCtx.new

      def initialize
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
        LibMonocypher.blake2b_init(pointerof(@ctx))
      end

      # Returns the digest output size in bytes.
      def digest_size : Int32
        64
      end
    end
  end
end
