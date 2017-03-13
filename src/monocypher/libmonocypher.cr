@[Link("monocypher")]
lib LibMonoCypher
  fun memcmp = crypto_memcmp(p1 : Uint8T*, p2 : Uint8T*, n : LibC::Int) : LibC::Int
  alias Uint8T = UInt8
  fun zerocmp = crypto_zerocmp(p : Uint8T*, n : LibC::Int) : LibC::Int
  fun chacha20_h = crypto_chacha20_H(out : Uint8T[32], key : Uint8T[32], in : Uint8T[16])
  fun chacha20_init = crypto_chacha20_init(ctx : ChachaCtx*, key : Uint8T[32], nonce : Uint8T[8])

  struct ChachaCtx
    input : Uint32T[16]
    random_pool : Uint8T[64]
    pool_index : Uint8T
  end

  alias Uint32T = LibC::UInt
  fun chacha20_xinit = crypto_chacha20_Xinit(ctx : ChachaCtx*, key : Uint8T[32], nonce : Uint8T[24])
  fun chacha20_encrypt = crypto_chacha20_encrypt(ctx : ChachaCtx*, cipher_text : Uint8T*, plain_text : Uint8T*, message_size : LibC::Int)
  fun chacha20_stream = crypto_chacha20_stream(ctx : ChachaCtx*, cipher_text : Uint8T*, message_size : LibC::Int)
  fun poly1305_init = crypto_poly1305_init(ctx : Poly1305Ctx*, key : Uint8T[32])

  struct Poly1305Ctx
    r : Uint32T[4]
    h : Uint32T[5]
    c : Uint32T[5]
    pad : Uint32T[5]
    c_index : LibC::Int
  end

  fun poly1305_update = crypto_poly1305_update(ctx : Poly1305Ctx*, m : Uint8T*, bytes : LibC::Int)
  fun poly1305_final = crypto_poly1305_final(ctx : Poly1305Ctx*, mac : Uint8T[16])
  fun poly1305_auth = crypto_poly1305_auth(mac : Uint8T[16], msg : Uint8T*, msg_size : LibC::Int, key : Uint8T[32])
  fun blake2b_general_init = crypto_blake2b_general_init(ctx : Blake2bCtx*, out_size : LibC::Int, key : Uint8T*, key_size : LibC::Int)

  struct Blake2bCtx
    buf : Uint8T[128]
    hash : Uint64T[8]
    input_size : Uint64T[2]
    c : Uint8T
    output_size : Uint8T
  end

  alias Uint64T = LibC::ULong
  fun blake2b_init = crypto_blake2b_init(ctx : Blake2bCtx*)
  fun blake2b_update = crypto_blake2b_update(ctx : Blake2bCtx*, in : Uint8T*, in_size : LibC::Int)
  fun blake2b_final = crypto_blake2b_final(ctx : Blake2bCtx*, out : Uint8T*)
  fun blake2b_general = crypto_blake2b_general(out : Uint8T*, out_size : LibC::Int, key : Uint8T*, key_size : LibC::Int, in : Uint8T*, in_size : LibC::Int)
  fun blake2b = crypto_blake2b(out : Uint8T[64], in : Uint8T*, in_size : LibC::Int)
  fun argon2i = crypto_argon2i(tag : Uint8T*, tag_size : Uint32T, work_area : Void*, nb_blocks : Uint32T, nb_iterations : Uint32T, password : Uint8T*, password_size : Uint32T, salt : Uint8T*, salt_size : Uint32T, key : Uint8T*, key_size : Uint32T, ad : Uint8T*, ad_size : Uint32T)
  fun x25519 = crypto_x25519(shared_secret : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32]) : LibC::Int
  fun x25519_public_key = crypto_x25519_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun sign_public_key = crypto_sign_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun sign = crypto_sign(signature : Uint8T[64], secret_key : Uint8T[32], public_key : Uint8T[32], message : Uint8T*, message_size : LibC::Int)
  fun check = crypto_check(signature : Uint8T[64], public_key : Uint8T[32], message : Uint8T*, message_size : LibC::Int) : LibC::Int
  fun key_exchange = crypto_key_exchange(shared_key : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32]) : LibC::Int
  fun aead_lock = crypto_aead_lock(mac : Uint8T*, ciphertext : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], ad : Uint8T*, ad_size : LibC::Int, plaintext : Uint8T*, text_size : LibC::Int)
  fun aead_unlock = crypto_aead_unlock(plaintext : Uint8T*, key : Uint8T[32], nonce : Uint8T*, mac : Uint8T*, ad : Uint8T*, ad_size : LibC::Int, ciphertext : Uint8T*, text_size : LibC::Int) : LibC::Int
  fun lock = crypto_lock(box : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], plaintext : Uint8T*, text_size : LibC::Int)
  fun unlock = crypto_unlock(plaintext : Uint8T*, key : Uint8T[32], nonce : Uint8T*, box : Uint8T*, box_size : LibC::Int) : LibC::Int
end
