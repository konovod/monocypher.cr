require "./spec_helper"

describe "LibMonocypher" do
  # TODO - add more tests from recent version

  it "test_aead" do
    key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)
    nonce = UInt8.static_array(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    ad = UInt8.static_array(3, 2, 1, 0)
    plaintext = UInt8.static_array(7, 6, 5, 4, 3, 2, 1, 0)
    mac = StaticArray(UInt8, 16).new(0_u8)
    smallbox = StaticArray(UInt8, 8).new(0_u8)
    aout = StaticArray(UInt8, 24).new(0_u8)
    # AEAD roundtrip
    LibMonocypher.aead_lock(smallbox, mac, key, nonce, ad, 4, plaintext, 8)
    LibMonocypher.aead_unlock(aout, mac, key, nonce, ad, 4, smallbox, 8).should eq 0
    aout.to_slice[0, 8].should eq plaintext.to_slice
    mac[0] += 1
    LibMonocypher.aead_unlock(aout, mac, key, nonce, ad, 4, smallbox, 8).should_not eq 0
  end
end
