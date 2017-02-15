require "secure_random"
require "./monocypher/*"


module Crypto
  MUCH_MB = 1

macro random_record(name, size)
  struct {{name}}
    @data : StaticArray(UInt8, {{size}})

    def initialize()
      @data = uninitialized UInt8[{{size}}]
      value = SecureRandom.random_bytes({{size}})
      {{size}}.times do |i|
        @data[i] = value[i]
      end
    end

    def to_unsafe
      @data
    end

    def to_pointer
      @data.to_unsafe
    end
    def to_slice
      @data.to_slice
    end
    def self.size
      {{size}}
    end
  end
end

macro just_record(name, size, *, default_init = false)
  struct {{name}}
    @data : StaticArray(UInt8, {{size}})
    {% if default_init %}
      def initialize()
        @data = StaticArray(UInt8, {{size}}).new(0_u8)
      end
    {% end %}
    def to_unsafe
      @data
    end
    def self.size
      {{size}}
    end
  end
end

random_record(SymmetricKey, 32)
random_record(Salt, 16)
random_record(Nonce, 24)
just_record(Header, 16, default_init: true)
random_record(SecretKey, 32)
just_record(PublicKey, 32)

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
    LibMonoCypher.ed25519_public_key(@data, secret)
  end
end


def self.symmetric_encrypt(*, output : Bytes, key : SymmetricKey, nonce : Nonce, input)
  raise "data sizes doesn't match" if input.size+Header.size+Nonce.size != output.size
  LibMonoCypher.ae_lock(output[Nonce.size, Header.size+input.size], key, nonce, input, input.size)
  output[0, Nonce.size].copy_from(nonce.to_slice)
end

def self.symmetric_decrypt(*, output : Bytes, key : SymmetricKey, input): Bool
  raise "data sizes doesn't match" if input.size != output.size+Header.size+Nonce.size
  nonce = Nonce.new
  nonce.to_slice.copy_from(input[0, Nonce.size])
  return LibMonoCypher.ae_unlock(output, key, nonce, input[Nonce.size, Header.size+output.size], output.size) == 0
end


end
