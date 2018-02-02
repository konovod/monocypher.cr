require "./libmonocypher"

module Crypto
  def self.sha512(data : Bytes) : Bytes
    Bytes.new(512/8).tap do |result|
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
end
