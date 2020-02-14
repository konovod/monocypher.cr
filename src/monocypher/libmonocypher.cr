@[Link("monocypher", ldflags: "-L#{__DIR__}/../../.build")]
lib LibMonocypher
  alias SizeT = LibC::SizeT
  alias Uint8T = UInt8
  alias Uint32T = UInt32
  alias Uint64T = UInt64

  fun verify16 = crypto_verify16(a : Uint8T[16], b : Uint8T[16]) : LibC::Int
  fun verify32 = crypto_verify32(a : Uint8T[32], b : Uint8T[32]) : LibC::Int
  fun verify64 = crypto_verify64(a : Uint8T[64], b : Uint8T[64]) : LibC::Int
  fun wipe = crypto_wipe(secret : Void*, size : SizeT)

  # fun lock = crypto_lock(mac : Uint8T[16], cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], plain_text : Uint8T*, text_size : SizeT)
  # fun unlock = crypto_unlock(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], mac : Uint8T[16], cipher_text : Uint8T*, text_size : SizeT) : LibC::Int
  # fun lock_aead = crypto_lock_aead(mac : Uint8T[16], cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], ad : Uint8T*, ad_size : SizeT, plain_text : Uint8T*, text_size : SizeT)
  # fun unlock_aead = crypto_unlock_aead(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T[24], mac : Uint8T[16], ad : Uint8T*, ad_size : SizeT, cipher_text : Uint8T*, text_size : SizeT) : LibC::Int
  # fun lock_init = crypto_lock_init(ctx : LockCtx*, key : Uint8T[32], nonce : Uint8T[24])
  # losing type safety to avoid excessive copying
  fun lock = crypto_lock(mac : Uint8T*, cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T*, plain_text : Uint8T*, text_size : SizeT)
  fun unlock = crypto_unlock(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T*, mac : Uint8T*, cipher_text : Uint8T*, text_size : SizeT) : LibC::Int
  fun lock_aead = crypto_lock_aead(mac : Uint8T*, cipher_text : Uint8T*, key : Uint8T[32], nonce : Uint8T*, ad : Uint8T*, ad_size : SizeT, plain_text : Uint8T*, text_size : SizeT)
  fun unlock_aead = crypto_unlock_aead(plain_text : Uint8T*, key : Uint8T[32], nonce : Uint8T*, mac : Uint8T*, ad : Uint8T*, ad_size : SizeT, cipher_text : Uint8T*, text_size : SizeT) : LibC::Int

  struct Blake2bCtx
    hash : Uint64T[8]
    input_offset : Uint64T[2]
    input : Uint64T[16]
    input_idx : SizeT
    hash_size : SizeT
  end

  fun blake2b = crypto_blake2b(hash : Uint8T[64], message : Uint8T*, message_size : SizeT)
  fun blake2b_general = crypto_blake2b_general(hash : Uint8T*, hash_size : SizeT, key : Uint8T*, key_size : SizeT, message : Uint8T*, message_size : SizeT)
  fun blake2b_init = crypto_blake2b_init(ctx : Blake2bCtx*)
  fun blake2b_update = crypto_blake2b_update(ctx : Blake2bCtx*, message : Uint8T*, message_size : SizeT)
  fun blake2b_final = crypto_blake2b_final(ctx : Blake2bCtx*, hash : Uint8T*)
  fun blake2b_general_init = crypto_blake2b_general_init(ctx : Blake2bCtx*, hash_size : SizeT, key : Uint8T*, key_size : SizeT)

  fun argon2i = crypto_argon2i(hash : Uint8T*, hash_size : Uint32T, work_area : Void*, nb_blocks : Uint32T, nb_iterations : Uint32T, password : Uint8T*, password_size : Uint32T, salt : Uint8T*, salt_size : Uint32T)
  fun argon2i_general = crypto_argon2i_general(hash : Uint8T*, hash_size : Uint32T, work_area : Void*, nb_blocks : Uint32T, nb_iterations : Uint32T, password : Uint8T*, password_size : Uint32T, salt : Uint8T*, salt_size : Uint32T, key : Uint8T*, key_size : Uint32T, ad : Uint8T*, ad_size : Uint32T)
  fun key_exchange = crypto_key_exchange(shared_key : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32])

  fun sign_public_key = crypto_sign_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun sign = crypto_sign(signature : Uint8T[64], secret_key : Uint8T[32], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT)
  fun check = crypto_check(signature : Uint8T[64], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT) : LibC::Int

  struct SignVtable
    hash : (Uint8T[64], Uint8T*, SizeT -> Void)
    init : (Void* -> Void)
    update : (Void*, Uint8T*, SizeT -> Void)
    final : (Void*, Uint8T[64] -> Void)
    ctx_size : SizeT
  end

  $blake2b_vtable : SignVtable
  $sha512_vtable : SignVtable

  struct SignCtxAbstract
    hash : SignVtable*
    buf : Uint8T[96]
    pk : Uint8T[32]
  end

  alias CheckCtxAbstract = SignCtxAbstract

  fun sign_init_first_pass = crypto_sign_init_first_pass(ctx : SignCtxAbstract*, secret_key : Uint8T[32], public_key : Uint8T[32])
  fun sign_update = crypto_sign_update(ctx : SignCtxAbstract*, message : Uint8T*, message_size : SizeT)
  fun sign_init_second_pass = crypto_sign_init_second_pass(ctx : SignCtxAbstract*)
  fun sign_final = crypto_sign_final(ctx : SignCtxAbstract*, signature : Uint8T[64])
  fun check_init = crypto_check_init(ctx : CheckCtxAbstract*, signature : Uint8T[64], public_key : Uint8T[32])
  fun check_update = crypto_check_update(ctx : CheckCtxAbstract*, message : Uint8T*, message_size : SizeT)
  fun check_final = crypto_check_final(ctx : CheckCtxAbstract*) : LibC::Int
  fun sign_public_key_custom_hash = crypto_sign_public_key_custom_hash(public_key : Uint8T[32], secret_key : Uint8T[32], hash : SignVtable*)
  fun sign_init_first_pass_custom_hash = crypto_sign_init_first_pass_custom_hash(ctx : SignCtxAbstract*, secret_key : Uint8T[32], public_key : Uint8T[32], hash : SignVtable*)
  fun check_init_custom_hash = crypto_check_init_custom_hash(ctx : CheckCtxAbstract*, signature : Uint8T[64], public_key : Uint8T[32], hash : SignVtable*)

  fun hchacha20 = crypto_hchacha20(out : Uint8T[32], key : Uint8T[32], in : Uint8T[16])
  fun chacha20 = crypto_chacha20(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[8])
  fun xchacha20 = crypto_xchacha20(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[24])
  fun ietf_chacha20 = crypto_ietf_chacha20(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[12])
  fun chacha20_ctr = crypto_chacha20_ctr(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[8], ctr : Uint64T) : Uint64T
  fun xchacha20_ctr = crypto_xchacha20_ctr(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[24], ctr : Uint64T) : Uint64T
  fun ietf_chacha20_ctr = crypto_ietf_chacha20_ctr(cipher_text : Uint8T*, plain_text : Uint8T*, text_size : SizeT, key : Uint8T[32], nonce : Uint8T[12], ctr : Uint32T) : Uint32T

  struct Poly1305Ctx
    r : Uint32T[4]
    h : Uint32T[5]
    c : Uint32T[5]
    pad : Uint32T[4]
    c_idx : SizeT
  end

  fun poly1305 = crypto_poly1305(mac : Uint8T[16], message : Uint8T*, message_size : SizeT, key : Uint8T[32])
  fun poly1305_init = crypto_poly1305_init(ctx : Poly1305Ctx*, key : Uint8T[32])
  fun poly1305_update = crypto_poly1305_update(ctx : Poly1305Ctx*, message : Uint8T*, message_size : SizeT)
  fun poly1305_final = crypto_poly1305_final(ctx : Poly1305Ctx*, mac : Uint8T[16])

  fun x25519_public_key = crypto_x25519_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun x25519 = crypto_x25519(raw_shared_secret : Uint8T[32], your_secret_key : Uint8T[32], their_public_key : Uint8T[32]) : LibC::Int

  struct Sha512Ctx
    hash : Uint64T[8]
    input : Uint64T[16]
    input_size : Uint64T[2]
    input_idx : SizeT
  end

  fun sha512_init = crypto_sha512_init(ctx : Sha512Ctx*)
  fun sha512_update = crypto_sha512_update(ctx : Sha512Ctx*, message : Uint8T*, message_size : SizeT)
  fun sha512_final = crypto_sha512_final(ctx : Sha512Ctx*, hash : Uint8T*)
  fun sha512 = crypto_sha512(hash : Uint8T*, message : Uint8T*, message_size : SizeT)

  struct HmacSha512Ctx
    key : Uint8T[128]
    ctx : Sha512Ctx
  end

  fun hmac_sha512_init = crypto_hmac_sha512_init(ctx : HmacSha512Ctx*, key : Uint8T*, key_size : SizeT)
  fun hmac_sha512_update = crypto_hmac_sha512_update(ctx : HmacSha512Ctx*, message : Uint8T*, message_size : SizeT)
  fun hmac_sha512_final = crypto_hmac_sha512_final(ctx : HmacSha512Ctx*, hmac : Uint8T[64])
  fun hmac_sha512 = crypto_hmac_sha512(hmac : Uint8T[64], key : Uint8T*, key_size : SizeT, message : Uint8T*, message_size : SizeT)
  fun ed25519_public_key = crypto_ed25519_public_key(public_key : Uint8T[32], secret_key : Uint8T[32])
  fun ed25519_sign = crypto_ed25519_sign(signature : Uint8T[64], secret_key : Uint8T[32], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT)
  fun ed25519_check = crypto_ed25519_check(signature : Uint8T[64], public_key : Uint8T[32], message : Uint8T*, message_size : SizeT) : LibC::Int
  fun ed25519_sign_init_first_pass = crypto_ed25519_sign_init_first_pass(ctx : SignCtxAbstract*, secret_key : Uint8T[32], public_key : Uint8T[32])
  fun ed25519_check_init = crypto_ed25519_check_init(ctx : CheckCtxAbstract*, signature : Uint8T[64], public_key : Uint8T[32])
end
