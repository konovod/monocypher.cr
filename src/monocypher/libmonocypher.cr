@[Link("monocypher", ldflags: "-L./../../.build/")]
lib LibMonocypher
  alias SizeT = LibC::SizeT
  alias Uint8T = UInt8
  alias Uint32T = UInt32
  alias Uint64T = UInt64

  fun verify16 = crypto_verify16(a : Uint8T[16], b : Uint8T[16]) : LibC::Int
  fun verify32 = crypto_verify32(a : Uint8T[32], b : Uint8T[32]) : LibC::Int
  fun verify64 = crypto_verify64(a : Uint8T[64], b : Uint8T[64]) : LibC::Int
  fun wipe = crypto_wipe(secret : Void*, size : SizeT)
  fun lock = crypto_lock(mac : Uint8T[16], cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], plain_text : Uint8T*, text_size : SizeT)
  fun unlock = crypto_unlock(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], mac : Uint8T[16], cipher_text : Uint8T*, text_size : SizeT) : LibC::Int
  fun aead_lock = crypto_aead_lock(mac : Uint8T[16], cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], ad : Uint8T*, ad_size : SizeT, plain_text : Uint8T*, text_size : SizeT)
  fun aead_unlock = crypto_aead_unlock(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], mac : Uint8T[16], ad : Uint8T*, ad_size : SizeT, cipher_text : Uint8T*, text_size : SizeT) : LibC::Int
  fun lock_init = crypto_lock_init(ctx : LockCtx*, key : Uint8T[32], nonce : Uint8T[24])

  struct LockCtx
    chacha : ChachaCtx
    poly : Poly1305Ctx
  end

  struct ChachaCtx
    input : Uint32T[16]
    pool : Uint32T[16]
    pool_idx : SizeT
  end

  struct Poly1305Ctx
    r : Uint32T[4]
    h : Uint32T[5]
    c : Uint32T[5]
    pad : Uint32T[4]
    c_idx : SizeT
  end

  fun lock_update = crypto_lock_update(ctx : LockCtx*, cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT)
  fun lock_final = crypto_lock_final(ctx : LockCtx*, mac : Uint8T[16])
  fun unlock_update = crypto_unlock_update(ctx : LockCtx*, plain_text : Uint8T*, cipher_text : Uint8T*, text_size : SizeT)
  fun unlock_final = crypto_unlock_final(ctx : LockCtx*, mac : Uint8T[16]) : SizeT
  fun blake2b = crypto_blake2b(hash : Uint8T[64], message : Uint8T*, message_size : SizeT)
  fun blake2b_general = crypto_blake2b_general(hash : Uint8T*, hash_size : SizeT, key : Uint8T*, key_size : SizeT, message : Uint8T*, message_size : SizeT)
  fun blake2b_init = crypto_blake2b_init(ctx : Blake2bCtx*)

  struct Blake2bCtx
    hash : Uint64T[8]
    input_offset : Uint64T[2]
    input : Uint64T[16]
    input_idx : SizeT
    hash_size : SizeT
  end

  fun blake2b_update = crypto_blake2b_update(ctx : Blake2bCtx*, message : Uint8T*, message_size : SizeT)
  fun blake2b_final = crypto_blake2b_final(ctx : Blake2bCtx*, hash : Uint8T*)
  fun blake2b_general_init = crypto_blake2b_general_init(ctx : Blake2bCtx*, hash_size : SizeT, key : Uint8T*, key_size : SizeT)
  fun argon2i = crypto_argon2i(hash : Uint8T*, hash_size : Uint32T, work_area : Void*, nb_blocks : Uint32T, nb_iterations : Uint32T, password : Uint8T*, password_size : Uint32T, salt : Uint8T*, salt_size : Uint32T)
  fun argon2i_general = crypto_argon2i_general(hash : Uint8T*, hash_size : Uint32T, work_area : Void*, nb_blocks : Uint32T, nb_iterations : Uint32T, password : Uint8T*, password_size : Uint32T, salt : Uint8T*, salt_size : Uint32T, key : Uint8T*, key_size : Uint32T, ad : Uint8T*, ad_size : Uint32T)
  fun key_exchange = crypto_key_exchange(shared_key : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32]) : LibC::Int
  fun sign_public_key = crypto_sign_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun sign = crypto_sign(signature : Uint8T[64], secret_key : Uint8T[32], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT)
  fun check = crypto_check(signature : Uint8T[64], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT) : LibC::Int
  fun sign_init_first_pass = crypto_sign_init_first_pass(ctx : SignCtx*, secret_key : Uint8T[32], public_key : Uint8T[32])

  struct SignCtx
    hash : HashCtx
    buf : Uint8T[96]
    pk : Uint8T[32]
  end

  alias HashCtx = Blake2bCtx
  fun sign_update = crypto_sign_update(ctx : SignCtx*, message : Uint8T*, message_size : SizeT)
  fun sign_init_second_pass = crypto_sign_init_second_pass(ctx : SignCtx*)
  fun sign_final = crypto_sign_final(ctx : SignCtx*, signature : Uint8T[64])
  fun check_init = crypto_check_init(ctx : CheckCtx*, signature : Uint8T[64], public_key : Uint8T[32])

  struct CheckCtx
    hash : HashCtx
    sig : Uint8T[64]
    pk : Uint8T[32]
  end

  fun check_update = crypto_check_update(ctx : CheckCtx*, message : Uint8T*, message_size : SizeT)
  fun check_final = crypto_check_final(ctx : CheckCtx*) : LibC::Int
  fun chacha20_h = crypto_chacha20_H(out : Uint8T[32], key : Uint8T[32], in : Uint8T[16])
  fun chacha20_init = crypto_chacha20_init(ctx : ChachaCtx*, key : Uint8T[32], nonce : Uint8T[8])
  fun chacha20_x_init = crypto_chacha20_x_init(ctx : ChachaCtx*, key : Uint8T[32], nonce : Uint8T[24])
  fun chacha20_set_ctr = crypto_chacha20_set_ctr(ctx : ChachaCtx*, ctr : Uint64T)
  fun chacha20_encrypt = crypto_chacha20_encrypt(ctx : ChachaCtx*, cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT)
  fun chacha20_stream = crypto_chacha20_stream(ctx : ChachaCtx*, stream : Uint8T*, size : SizeT)
  fun poly1305 = crypto_poly1305(mac : Uint8T[16], message : Uint8T*, message_size : SizeT, key : Uint8T[32])
  fun poly1305_init = crypto_poly1305_init(ctx : Poly1305Ctx*, key : Uint8T[32])
  fun poly1305_update = crypto_poly1305_update(ctx : Poly1305Ctx*, message : Uint8T*, message_size : SizeT)
  fun poly1305_final = crypto_poly1305_final(ctx : Poly1305Ctx*, mac : Uint8T[16])
  fun x25519_public_key = crypto_x25519_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun x25519 = crypto_x25519(raw_shared_secret : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32]) : LibC::Int
  fun lock_encrypt = crypto_lock_encrypt(ctx : LockCtx*, cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT)
  fun lock_auth = crypto_lock_auth(ctx : LockCtx*, message : Uint8T*, message_size : SizeT)
  fun sha512_init = crypto_sha512_init(ctx : Sha512Ctx*)

  struct Sha512Ctx
    w : Uint64T[80]
    hash : Uint64T[8]
    input : Uint64T[16]
    input_size : Uint64T[2]
    input_idx : SizeT
  end

  fun sha512_update = crypto_sha512_update(ctx : Sha512Ctx*, message : Uint8T*, message_size : SizeT)
  fun sha512_final = crypto_sha512_final(ctx : Sha512Ctx*, hash : Uint8T[64])
  fun sha512 = crypto_sha512(out : Uint8T*, message : Uint8T*, message_size : SizeT)
end
