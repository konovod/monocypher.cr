require "./spec_helper"

describe "LibMonoCypher" do
  # status |= generic_test(equal, "vectors_test_equal", 2);
  # status |= generic_test(diff , "vectors_test_diff" , 2);
  # status |= test(chacha20,  "vectors_chacha20", 2);
  # status |= test(blake2b ,  "vectors_blake2b" , 2);
  # status |= test(poly1305,  "vectors_poly1305", 2);
  # status |= test(argon2i ,  "vectors_argon2i" , 6);
  # status |= test(x25519  ,  "vectors_x25519"  , 2);
  # status |= test(sha512  ,  "vectors_sha512"  , 1);
  # status |= test(ed25519 ,  "vectors_ed25519" , 3);
  # status |= test_x25519();
  # status |= test_ae();
  # status |= test_lock();

  it "memcmp" do
    ptr1 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr2 = Pointer.malloc(9) { |i| ('a'.ord + i).to_u8 }
    ptr3 = Pointer.malloc(9) { |i| i == 8 ? 0u8 : ('a'.ord + i).to_u8 }
    LibMonoCypher.memcmp(ptr1, ptr2, 9).should eq 0
    LibMonoCypher.memcmp(ptr1, ptr3, 9).should_not eq 0
  end

  it "test_ae" do
    key = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)
    nonce = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)
    plaintext = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7)
    box = StaticArray(UInt8, 24).new(0_u8)
    aout = StaticArray(UInt8, 24).new(0_u8)
    LibMonoCypher.ae_lock(box, key, nonce, plaintext, 8)          # make true message
    LibMonoCypher.ae_unlock(aout, key, nonce, box, 8).should eq 0 # accept true message
    LibMonoCypher.memcmp(aout, plaintext, 8).should eq 0          # roundtrip
    box[0] += 1
    LibMonoCypher.ae_unlock(aout, key, nonce, box, 8).should_not eq 0 # reject forgery
  end

  it "test_lock" do
    rk = UInt8.static_array(1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0,
      1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0)
    sk = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
      0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7)
    pk = StaticArray(UInt8, 32).new(0_u8)
    LibMonoCypher.x25519_public_key(pk, sk)
    plaintext = UInt8.static_array(0, 1, 2, 3, 4, 5, 6, 7)
    box = StaticArray(UInt8, 56).new(0_u8)
    aout = StaticArray(UInt8, 8).new(56_u8)
    LibMonoCypher.anonymous_lock(box, rk, pk, plaintext, 8)
    LibMonoCypher.anonymous_unlock(aout, sk, box, 8).should eq 0
    LibMonoCypher.memcmp(aout, plaintext, 8).should eq 0
    box[32] += 1
    LibMonoCypher.anonymous_unlock(aout, sk, box, 8).should_not eq 0
  end
end
