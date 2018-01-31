require "./spec_helper"

describe "LibMonocypher" do
  # two tests from old version of monocypher
  # TODO - add more tests from recent version

  it "memcmp" do
    ptr1 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr2 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr3 = Pointer.malloc(9) { |i| i == 8 ? 0u8 : ('a'.ord + i).to_u8 }
    LibMonocypher.memcmp(ptr1, ptr2, 9).should eq 0
    LibMonocypher.memcmp(ptr1, ptr3, 9).should_not eq 0
  end

  it "test_aead" do
    key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)
    nonce = UInt8.static_array(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1)
    ad = UInt8.static_array(3, 2, 1, 0)
    plaintext = UInt8.static_array(7, 6, 5, 4, 3, 2, 1, 0)
    box = StaticArray(UInt8, 24).new(0_u8)
    mac = StaticArray(UInt8, 16).new(0_u8)
    smallbox = StaticArray(UInt8, 8).new(0_u8)
    aout = StaticArray(UInt8, 24).new(0_u8)
    # AEAD roundtrip
    LibMonocypher.aead_lock(mac, smallbox, key, nonce, ad, 4, plaintext, 8)
    LibMonocypher.aead_unlock(aout, key, nonce, mac, ad, 4, smallbox, 8).should eq 0
    LibMonocypher.memcmp(plaintext, aout, 8).should eq 0
    mac[0] += 1
    LibMonocypher.aead_unlock(aout, key, nonce, mac, ad, 4, smallbox, 8).should_not eq 0

    # Authenticated roundtrip (easy interface)
    # LibMonocypher.lock(box, key, nonce, plaintext, 8)
    # LibMonocypher.unlock(aout, key, nonce, box, 8 + 16).should eq 0
    # LibMonocypher.memcmp(plaintext, aout, 8).should eq 0
    # box[0] += 1
    # LibMonocypher.unlock(aout, key, nonce, box, 8 + 16).should_not eq 0
    # box[0] -= 1
    #
    # # Same result for both interfaces
    # LibMonocypher.aead_lock(mac, smallbox, key, nonce, nil, 0, plaintext, 8)
    # LibMonocypher.memcmp(mac, box, 16).should eq 0
    # LibMonocypher.memcmp(smallbox, box.to_slice[16, 8], 8).should eq 0
  end
end
