require "./spec_helper"
require "benchmark"
require "digest/sha512"

x1 = x2 = x3 = x4 = nil
Benchmark.ips do |bench|
  digest1 = Digest::SHA512.new
  buffer = Bytes.new(1024)
  Random::Secure.random_bytes(buffer)
  bench.report("stdlib") do
    digest1.reset
    digest1 << buffer
    x1 = digest1.final
  end
  digest2 = Crypto::Digest::SHA512.new
  bench.report("Monocypher sha512") do
    digest2.reset
    digest2 << buffer
    x2 = digest2.final
  end
  digest3 = Crypto::Digest::BLAKE2b.new
  bench.report("Monocypher blake2b") do
    digest3.reset
    digest3 << buffer
    x3 = digest3.final
  end
  bench.report("Monocypher blake2b direct") do
    x4 = Crypto.blake2b(buffer)
  end
end
puts x1, x2, x3, x4
