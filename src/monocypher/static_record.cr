module StaticRecord
  macro declare(name, size, initialization = :none)
    struct {{name}}
      @data : StaticArray(UInt8, {{size}})

      {% if initialization == :zero %}
        def initialize()
          @data = StaticArray(UInt8, {{size}}).new(0_u8)
        end
      {% end %}
      {% if initialization == :random %}
      def reroll
        value = SecureRandom.random_bytes({{size}})
        @data.to_unsafe.copy_from(value.to_unsafe, {{size}})
      end

      def initialize()
        @data = uninitialized UInt8[{{size}}]
        reroll
      end
      {% end %}

      def to_unsafe
        @data
      end

      def compare(other) : Bool
        return typeof(other) == typeof(self) && LibMonoCypher.memcmp(to_unsafe, other.to_unsafe, self.class.size) == 0
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
end
