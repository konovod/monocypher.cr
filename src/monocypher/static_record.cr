
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
      def initialize()
        @data = uninitialized UInt8[{{size}}]
        value = SecureRandom.random_bytes({{size}})
        {{size}}.times do |i|
          @data[i] = value[i]
        end
      end
      {% end %}

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

end
