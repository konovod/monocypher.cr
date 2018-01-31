require "random/secure"
require "crypto/subtle"

module StaticRecord
  macro declare(name, size, initialization = :none)
    struct {{name}}
      @data : StaticArray(UInt8, {{size}})

{% if initialization == :zero %}
      def initialize
        @data = StaticArray(UInt8, {{size}}).new(0_u8)
      end
{% end %}

{% if initialization == :random %}
      def reroll
        Random::Secure.random_bytes(@data.to_slice)
      end

      def initialize
        @data = uninitialized UInt8[{{size}}]
        reroll
      end
{% end %}

      def initialize(s : String)
        @data = uninitialized UInt8[{{size}}]
        required_length = 2*{{size}}
        raise "string size should be #{required_length}, not #{s.size}" if s.size != required_length
        values = s.hexbytes
        @data.to_unsafe.copy_from(values.to_unsafe, {{size}})
      end

      def self.from_bytes(raw : Bytes)
        raise "bytes size should be #{ {{size}} }, not #{raw.size}" if raw.size != {{size}}
        raw.to_unsafe.as(Pointer({{name}})).value
      end

      def to_unsafe
        @data
      end

      def compare(other) : Bool
        return Crypto::Subtle.constant_time_compare(to_slice, other.to_slice)
      end

      def to_slice
        @data.to_slice
      end

      def self.size
        {{size}}
      end
    end
  end
end
