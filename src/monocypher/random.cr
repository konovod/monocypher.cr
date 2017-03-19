# patching SecureRandom to provide non-allocating version of random_bytes
module SecureRandom
  private def self.getrandom_wrapped(buf : Bytes)
    # getrandom(2) may only read up to 256 bytes at once without being
    # interrupted or returning early
    chunk_size = 256

    while buf.size > 0
      if buf.size < chunk_size
        chunk_size = buf.size
      end

      read_bytes = getrandom(buf[0, chunk_size])
      raise Errno.new("getrandom") if read_bytes == -1

      buf += read_bytes
    end
  end

  def self.random_bytes(buf : Bytes)
    init unless @@initialized

    {% if flag?(:linux) %}
      if @@getrandom_available
        getrandom_wrapped(buf)
        return
      end
    {% end %}

    if urandom = @@urandom
      urandom.read_fully(buf)
      return
    end

    raise "Failed to access secure source to generate random bytes!"
  end
end
