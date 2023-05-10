@[Link("monocypher", ldflags: "-L#{__DIR__}/../../.build")]
lib LibMonocypher
  alias SizeT = LibC::SizeT

  # Constant time comparisons
  # --------------------------------------
  # Return 0 if a and b are equal, -1 otherwise

  fun verify16 = crypto_verify16(a : UInt8[16], b : UInt8[16]) : LibC::Int
  fun verify32 = crypto_verify32(a : UInt8[32], b : UInt8[32]) : LibC::Int
  fun verify64 = crypto_verify64(a : UInt8[64], b : UInt8[64]) : LibC::Int

  # Erase sensitive data
  # --------------------------------------
  fun wipe = crypto_wipe(secret : Void*, size : SizeT)

  # Authenticated encryption
  # --------------------------------------

  fun aead_lock = crypto_aead_lock(cipher_text : UInt8*, mac : UInt8*, key : UInt8[32], nonce : UInt8*, ad : UInt8*, ad_size : SizeT, plain_text : UInt8*, text_size : SizeT)
  fun aead_unlock = crypto_aead_unlock(plain_text : UInt8*, mac : UInt8*, key : UInt8[32], nonce : UInt8*, ad : UInt8*, ad_size : SizeT, cipher_text : UInt8*, text_size : SizeT) : LibC::Int

  # Authenticated stream
  # --------------------------------------

  struct CryptoAEADCtx
    counter : UInt64
    key : UInt8[32]
    nonce : UInt8[8]
  end

  fun aead_init_x = crypto_aead_init_x(ctx : CryptoAEADCtx*, key : UInt8[32], nonce : UInt8*)
  fun aead_init_djb = crypto_aead_init_djb(ctx : CryptoAEADCtx*, key : UInt8[32], nonce : UInt8*)
  fun aead_init_ietf = crypto_aead_init_ietf(ctx : CryptoAEADCtx*, key : UInt8[32], nonce : UInt8*)

  fun aead_write = crypto_aead_write(ctx : CryptoAEADCtx*, cipher_text : UInt8*, mac : UInt8*, ad : UInt8*, ad_size : SizeT, plain_text : UInt8*, text_size : SizeT)
  fun aead_read = crypto_aead_read(ctx : CryptoAEADCtx*, plain_text : UInt8*, mac : UInt8*, ad : UInt8*, ad_size : SizeT, cipher_text : UInt8*, text_size : SizeT) : LibC::Int

  # General purpose hash (BLAKE2b)
  # --------------------------------------

  # Direct interface

  fun blake2b = crypto_blake2b(hash : UInt8*, hash_size : SizeT, message : UInt8*, message_size : SizeT)
  fun blake2b_keyed = crypto_blake2b_keyed(hash : UInt8*, hash_size : SizeT, key : UInt8*, key_size : SizeT, message : UInt8*, message_size : SizeT)

  # Incremental interface

  struct Blake2bCtx
    hash : UInt64[8]
    input_offset : UInt64[2]
    input : UInt64[16]
    input_idx : SizeT
    hash_size : SizeT
  end

  fun blake2b_init = crypto_blake2b_init(ctx : Blake2bCtx*, hash_size : SizeT)
  fun blake2b_keyed_init = crypto_blake2b_general_init(ctx : Blake2bCtx*, hash_size : SizeT, key : UInt8*, key_size : SizeT)
  fun blake2b_update = crypto_blake2b_update(ctx : Blake2bCtx*, message : UInt8*, message_size : SizeT)
  fun blake2b_final = crypto_blake2b_final(ctx : Blake2bCtx*, hash : UInt8*)

  # Password key derivation (Argon2)
  # --------------------------------------

  enum Argon2Algorithm : UInt32
    D  = 0
    I  = 1
    ID = 2
  end

  struct Argon2Config
    algorithm : Argon2Algorithm
    nb_blocks : UInt32 # memory hardness, >= 8 * nb_lanes
    nb_passes : UInt32 # CPU hardness, >= 1 (>= 3 recommended for Argon2i)
    nb_lanes : UInt32  # parallelism level (single threaded anyway)
  end

  struct Argon2Inputs
    pass : UInt8*
    salt : UInt8*
    pass_size : UInt32
    salt_size : UInt32 # 16 bytes recommended
  end

  struct Argon2Extras
    key : UInt8*      #  may be NULL if no key
    ad : UInt8*       # may be NULL if no additional data
    key_size : UInt32 # 0 if no key (32 bytes recommended otherwise)
    ad_size : UInt32  # 0 if no additional data
  end

  $crypto_argon2_no_extras : Argon2Extras

  fun argon2 = crypto_argon2(hash : UInt8*, hash_size : UInt32, work_area : Void*, config : Argon2Config, inputs : Argon2Inputs, extras : Argon2Extras)

  # Key exchange (X-25519)
  # --------------------------------------
  # Shared secrets are not quite random.
  # Hash them to derive an actual shared key.

  fun x25519_public_key = crypto_x25519_public_key(public_key : UInt8[32], secret_key : UInt8[32])
  fun x25519 = crypto_x25519(raw_shared_secret : UInt8[32], your_secret_key : UInt8[32], their_public_key : UInt8[32])
  # Conversion to EdDSA
  fun x25519_to_eddsa = crypto_x25519_to_eddsa(eddsa : UInt8[32], x25519 : UInt8[32])

  # scalar "division"
  # Used for OPRF.  Be aware that exponential blinding is less secure than Diffie-Hellman key exchange.
  fun x25519_inverse = crypto_x25519_inverse(blind_salt : UInt8[32], private_key : UInt8[32], curve_point : UInt8[32])

  # "Dirty" versions of x25519_public_key().
  # Use with crypto_elligator_rev().
  # Leaks 3 bits of the private key.

  fun x25519_dirty_small = crypto_x25519_dirty_small(pk : UInt8[32], sk : UInt8[32])
  fun x25519_dirty_fast = crypto_x25519_dirty_fast(pk : UInt8[32], sk : UInt8[32])

  # Signatures1
  # --------------------------------------
  # EdDSA with curve25519 + BLAKE2b

  fun eddsa_key_pair = crypto_eddsa_key_pair(secret_key : UInt8[64], public_key : UInt8[32], seed : UInt8[32])
  fun eddsa_sign = crypto_eddsa_sign(signature : UInt8[64], secret_key : UInt8[64], message : UInt8*, message_size : SizeT)
  fun eddsa_check = crypto_eddsa_check(signature : UInt8[64], public_key : UInt8[32], message : UInt8*, message_size : SizeT) : LibC::Int

  # Conversion to X25519
  fun eddsa_to_x25519 = crypto_eddsa_to_x25519(x25519 : UInt8[32], eddsa : UInt8[32])

  # EdDSA building blocks

  fun eddsa_trim_scalar = crypto_eddsa_trim_scalar(out : UInt8[32], in : UInt8[32])
  fun eddsa_reduce = crypto_eddsa_reduce(reduced : UInt8[32], expanded : UInt8[64])
  fun eddsa_mul_add = crypto_eddsa_mul_add(r : UInt8[32], a : UInt8[32], b : UInt8[32], c : UInt8[32])
  fun eddsa_scalarbase = crypto_eddsa_scalarbase(point : UInt8[32], scalar : UInt8[32])
  fun eddsa_check_equation = crypto_eddsa_check_equation(signature : UInt8[64], public_key : UInt8[32], h_ram : UInt8[32]) : LibC::Int

  # Chacha20
  # --------------------------------------

  # Specialised hash.
  # Used to hash X25519 shared secrets.
  fun chacha20_h = crypto_chacha20_h(out : UInt8[32], key : UInt8[32], in : UInt8[16])

  # Unauthenticated stream cipher.
  # Don't forget to add authentication.

  fun chacha20_djb = crypto_chacha20_djb(cipher_text : UInt8*, plain_text : UInt8*, text_size : SizeT, key : UInt8[32], nonce : UInt8[8], ctr : UInt64) : UInt64
  fun chacha20_ietf = crypto_chacha20_ietf(cipher_text : UInt8*, plain_text : UInt8*, text_size : SizeT, key : UInt8[32], nonce : UInt8[12], ctr : UInt32) : UInt32
  fun chacha20_x = crypto_chacha20_x(cipher_text : UInt8*, plain_text : UInt8*, text_size : SizeT, key : UInt8[32], nonce : UInt8[24], ctr : UInt64) : UInt64

  # Poly 1305
  # --------------------------------------
  # This is a *one time* authenticator.
  # Disclosing the mac reveals the key.
  # See crypto_lock() on how to use it properly.

  # Direct interface
  fun poly1305 = crypto_poly1305(mac : UInt8[16], message : UInt8*, message_size : SizeT, key : UInt8[32])

  # Incremental interface

  struct Poly1305Ctx
    c : UInt8[16]   # chunk of the message
    c_idx : SizeT   # How many bytes are there in the chunk.
    r : UInt32[4]   # constant multiplier (from the secret key)
    pad : UInt32[4] # random number added at the end (from the secret key)
    h : UInt32[5]   #  accumulated hash
  end

  fun poly1305_init = crypto_poly1305_init(ctx : Poly1305Ctx*, key : UInt8[32])
  fun poly1305_update = crypto_poly1305_update(ctx : Poly1305Ctx*, message : UInt8*, message_size : SizeT)
  fun poly1305_final = crypto_poly1305_final(ctx : Poly1305Ctx*, mac : UInt8[16])

  # Elligator 2
  # --------------------------------------

  # Elligator mappings proper

  fun elligator_map = crypto_elligator_map(curve : UInt8[32], hidden : UInt8[32])
  fun elligator_rev = crypto_elligator_rev(hidden : UInt8[32], curve : UInt8[32], tweak : UInt8) : LibC::Int

  # Easy to use key pair generation
  fun elligator_key_pair = crypto_elligator_key_pair(hidden : UInt8[32], secret_key : UInt8[32], seed : UInt8[32])

  # SHA 512
  # --------------------------------------

  struct Sha512Ctx
    hash : UInt64[8]
    input : UInt64[16]
    input_size : UInt64[2]
    input_idx : SizeT
  end

  fun sha512_init = crypto_sha512_init(ctx : Sha512Ctx*)
  fun sha512_update = crypto_sha512_update(ctx : Sha512Ctx*, message : UInt8*, message_size : SizeT)
  fun sha512_final = crypto_sha512_final(ctx : Sha512Ctx*, hash : UInt8*)
  fun sha512 = crypto_sha512(hash : UInt8*, message : UInt8*, message_size : SizeT)

  # SHA 512 HMAC
  # --------------------------------------

  struct Sha512HmacCtx
    key : UInt8[128]
    ctx : Sha512Ctx
  end

  fun sha512_hmac_init = crypto_sha512_hmac_init(ctx : Sha512HmacCtx*, key : UInt8*, key_size : SizeT)
  fun sha512_hmac_update = crypto_sha512_hmac_update(ctx : Sha512HmacCtx*, message : UInt8*, message_size : SizeT)
  fun sha512_hmac_final = crypto_sha512_hmac_final(ctx : Sha512HmacCtx*, hmac : UInt8[64])
  fun sha512_hmac = crypto_sha512_hmac(hmac : UInt8[64], key : UInt8*, key_size : SizeT, message : UInt8*, message_size : SizeT)

  # SHA 512 HKDF
  # --------------------------------------

  fun sha512_hkdf_expand = crypto_sha512_hkdf_expand(okm : UInt8*, okm_size : SizeT, prk : UInt8*, prk_size : SizeT, info : UInt8*, info_size : SizeT)
  fun sha512_hkdf = crypto_sha512_hkdf(okm : UInt8*, okm_size : SizeT, ikm : UInt8*, ikm_size : SizeT, salt : UInt8*, salt_size : SizeT, info : UInt8*, info_size : SizeT)

  # Ed25519
  # --------------------------------------
  # Signatures (EdDSA with curve25519 + SHA-512)

  fun ed25519_key_pair = crypto_ed25519_key_pair(secret_key : UInt8[64], public_key : UInt8[32], seed : UInt8[32])
  fun ed25519_sign = crypto_ed25519_sign(signature : UInt8[64], secret_key : UInt8[64], message : UInt8*, message_size : SizeT)
  fun ed25519_check = crypto_ed25519_check(signature : UInt8[64], public_key : UInt8[32], message : UInt8*, message_size : SizeT) : LibC::Int

  # Pre-hash variants

  fun ed25519_ph_sign = crypto_ed25519_ph_sign(signature : UInt8[64], secret_key : UInt8[64], message_hash : UInt8[64])
  fun ed25519_ph_check = crypto_ed25519_ph_check(signature : UInt8[64], public_key : UInt8[32], message_hash : UInt8[64]) : LibC::Int
end
