require "./spec_helper"

TEST_VECTORS_SHA512 = [
  ["", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"],
]

# pp Crypto.blake2b("abc".to_slice, key: "".to_slice, hash_size: 64).hexstring
# pp Crypto.blake2b("abc".to_slice).hexstring

describe "Crypto.sha512" do
  it "pass test vectors from node.js" do
    TEST_VECTORS_SHA512.each do |(data, hash)|
      Crypto.sha512(data.to_slice).hexstring.should eq hash
    end
  end
end
