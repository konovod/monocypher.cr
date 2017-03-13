require "./spec_helper"

describe "LibMonoCypher" do
  # translated from monocypher test.c
  # not covered:
  # status |= test(chacha20     , "vectors_chacha20"    , 2);
  # status |= test(hchacha20    , "vectors_h_chacha20"  , 2);
  # status |= test(xchacha20    , "vectors_x_chacha20"  , 2);
  # status |= test(blake2b      , "vectors_blake2b"     , 2);
  # status |= test(blake2b_easy , "vectors_blake2b_easy", 1);
  # status |= test(poly1305     , "vectors_poly1305"    , 2);
  # status |= test(argon2i      , "vectors_argon2i"     , 6);
  # status |= test(x25519       , "vectors_x25519"      , 2);
  # status |= test(key_exchange , "vectors_key_exchange", 2);
  # status |= test(sha512       , "vectors_sha512"      , 1);
  # status |= test(ed25519_key  , "vectors_ed25519_key" , 1);
  # status |= test(ed25519_sign1, "vectors_ed25519_sign", 3);
  # status |= test(ed25519_sign2, "vectors_ed25519_sign", 3);
  # status |= test_x25519();

  it "memcmp" do
    ptr1 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr2 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr3 = Pointer.malloc(9) { |i| i == 8 ? 0u8 : ('a'.ord + i).to_u8 }
    LibMonoCypher.memcmp(ptr1, ptr2, 9).should eq 0
    LibMonoCypher.memcmp(ptr1, ptr3, 9).should_not eq 0
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
    LibMonoCypher.aead_lock(mac, smallbox, key, nonce, ad, 4, plaintext, 8)
    LibMonoCypher.aead_unlock(aout, key, nonce, mac, ad, 4, smallbox, 8).should eq 0
    LibMonoCypher.memcmp(plaintext, aout, 8).should eq 0
    mac[0] += 1
    LibMonoCypher.aead_unlock(aout, key, nonce, mac, ad, 4, smallbox, 8).should_not eq 0

    # Authenticated roundtrip (easy interface)
    LibMonoCypher.lock(box, key, nonce, plaintext, 8)
    LibMonoCypher.unlock(aout, key, nonce, box, 8 + 16).should eq 0
    LibMonoCypher.memcmp(plaintext, aout, 8).should eq 0
    box[0] += 1
    LibMonoCypher.unlock(aout, key, nonce, box, 8 + 16).should_not eq 0
    box[0] -= 1

    # Same result for both interfaces
    LibMonoCypher.aead_lock(mac, smallbox, key, nonce, nil, 0, plaintext, 8)
    LibMonoCypher.memcmp(mac, box, 16).should eq 0
    LibMonoCypher.memcmp(smallbox, box.to_slice[16, 8], 8).should eq 0
  end
end
