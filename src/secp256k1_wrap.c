#include <string.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/bigarray.h>
#include <caml/custom.h>
#include <caml/fail.h>

/* Accessing the secp256k1_context * part of an OCaml custom block */
#define Context_val(v) (*((secp256k1_context **) Data_custom_val(v)))

void context_destroy(value ctx) {
    secp256k1_context_destroy (Context_val(ctx));
}

static struct custom_operations secp256k1_context_ops = {
    .identifier = "secp256k1_context",
    .finalize = context_destroy,
    .compare = custom_compare_default,
    .compare_ext = custom_compare_ext_default,
    .hash = custom_hash_default,
    .serialize = custom_serialize_default,
    .deserialize = custom_deserialize_default
};

static value alloc_context (secp256k1_context *ctx) {
    value ml_ctx = caml_alloc_custom(&secp256k1_context_ops, sizeof(secp256k1_context *), 0, 1);
    Context_val(ml_ctx) = ctx;
    return ml_ctx;
}

CAMLprim value context_flags (value buf) {
    uint16_t *a = Caml_ba_data_val(buf);
    a[0] = SECP256K1_CONTEXT_NONE;
    a[1] = SECP256K1_CONTEXT_VERIFY;
    a[2] = SECP256K1_CONTEXT_SIGN;
    return Val_int(3 * sizeof(uint16_t));
}

CAMLprim value context_create (value flags) {
    CAMLparam1(flags);
    secp256k1_context *ctx = secp256k1_context_create (Int_val(flags));
    if (!ctx) caml_failwith("context_create");
    CAMLreturn(alloc_context(ctx));
}

CAMLprim value context_randomize (value ctx, value seed) {
    return Val_bool(secp256k1_context_randomize(Context_val(ctx),
                                                Caml_ba_data_val(seed)));
}

CAMLprim value context_clone (value ctx) {
    CAMLparam1(ctx);
    secp256k1_context *new = secp256k1_context_clone (Context_val(ctx));
    if (!new) caml_failwith("context_clone");
    CAMLreturn(alloc_context(new));
}

CAMLprim value ec_seckey_verify (value ctx, value sk) {
    return Val_bool(secp256k1_ec_seckey_verify(Caml_ba_data_val(ctx),
                                               Caml_ba_data_val(sk)));
}

CAMLprim value ec_privkey_negate(value ctx, value sk) {
    int ret = secp256k1_ec_seckey_negate(Context_val (ctx),
                                         Caml_ba_data_val(sk));
    return Val_unit;
}

CAMLprim value ec_privkey_tweak_add(value ctx, value sk, value tweak) {
    return Val_bool(secp256k1_ec_seckey_tweak_add(Caml_ba_data_val(ctx),
                                                   Caml_ba_data_val(sk),
                                                   Caml_ba_data_val(tweak)));
}

CAMLprim value ec_privkey_tweak_mul(value ctx, value sk, value tweak) {
    return Val_bool(secp256k1_ec_seckey_tweak_mul(Caml_ba_data_val(ctx),
                                                  Caml_ba_data_val(sk),
                                                  Caml_ba_data_val(tweak)));
}

CAMLprim value ec_pubkey_create (value ctx, value buf, value sk) {
    return Val_bool(secp256k1_ec_pubkey_create (Caml_ba_data_val(ctx),
                                                Caml_ba_data_val(buf),
                                                Caml_ba_data_val(sk)));
}

CAMLprim value ec_pubkey_serialize (value ctx, value buf, value pk) {
    size_t size = Caml_ba_array_val(buf)->dim[0];
    unsigned int flags =
        size == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

    secp256k1_ec_pubkey_serialize(Caml_ba_data_val(ctx),
                                  Caml_ba_data_val(buf),
                                  &size,
                                  Caml_ba_data_val(pk),
                                  flags);

    return Val_int(size);
}

CAMLprim value ec_pubkey_parse(value ctx, value buf, value pk) {
    return Val_bool(secp256k1_ec_pubkey_parse(Caml_ba_data_val(ctx),
                                              Caml_ba_data_val(buf),
                                              Caml_ba_data_val(pk),
                                              Caml_ba_array_val(pk)->dim[0]));
}

CAMLprim value ec_pubkey_negate(value ctx, value pk) {
    int ret = secp256k1_ec_pubkey_negate(Caml_ba_data_val(ctx),
                                         Caml_ba_data_val(pk));
    return Val_unit;
}

CAMLprim value ec_pubkey_tweak_add(value ctx, value pk, value tweak) {
    return Val_bool(secp256k1_ec_pubkey_tweak_add(Caml_ba_data_val(ctx),
                                                  Caml_ba_data_val(pk),
                                                  Caml_ba_data_val(tweak)));
}

CAMLprim value ec_pubkey_tweak_mul(value ctx, value pk, value tweak) {
    return Val_bool(secp256k1_ec_pubkey_tweak_mul(Caml_ba_data_val(ctx),
                                                  Caml_ba_data_val(pk),
                                                  Caml_ba_data_val(tweak)));
}

CAMLprim value ec_pubkey_combine(value ctx, value out, value pks) {
    int size = 0;
    const secp256k1_pubkey* cpks[1024] = {0};

    while(Field(pks, 1) != Val_unit) {
        cpks[size] = Caml_ba_data_val(Field(pks, 0));
        size++;
        pks = Field(pks, 1);
    }

    return Val_int(secp256k1_ec_pubkey_combine(Caml_ba_data_val(ctx),
                                               Caml_ba_data_val(out),
                                               cpks,
                                               size));
}

CAMLprim value ecdsa_signature_parse_compact (value ctx, value buf, value sig) {
    return Val_bool(secp256k1_ecdsa_signature_parse_compact (Caml_ba_data_val(ctx),
                                                             Caml_ba_data_val(buf),
                                                             Caml_ba_data_val(sig)));
}

CAMLprim value ecdsa_signature_parse_der (value ctx, value buf, value sig) {
    return Val_bool(secp256k1_ecdsa_signature_parse_der (Caml_ba_data_val(ctx),
                                                         Caml_ba_data_val(buf),
                                                         Caml_ba_data_val(sig),
                                                         Caml_ba_array_val(sig)->dim[0]));
}

CAMLprim value ecdsa_verify (value ctx, value pubkey, value msg, value signature) {
    return Val_bool(secp256k1_ecdsa_verify (Caml_ba_data_val(ctx),
                                            Caml_ba_data_val(signature),
                                            Caml_ba_data_val(msg),
                                            Caml_ba_data_val(pubkey)));
}


CAMLprim value ecdsa_sign (value ctx, value buf, value seckey, value msg) {
    return Val_bool(secp256k1_ecdsa_sign (Caml_ba_data_val(ctx),
                                          Caml_ba_data_val(buf),
                                          Caml_ba_data_val(msg),
                                          Caml_ba_data_val(seckey),
                                          NULL, NULL));
}

CAMLprim value ecdsa_signature_serialize_der(value ctx, value buf, value signature) {
    size_t size = Caml_ba_array_val(buf)->dim[0];
    int ret = secp256k1_ecdsa_signature_serialize_der(Caml_ba_data_val(ctx),
                                                      Caml_ba_data_val(buf),
                                                      &size,
                                                      Caml_ba_data_val(signature));

    return (ret == 0 ? Val_int(ret) : Val_int(size));
}

CAMLprim value ecdsa_signature_serialize_compact(value ctx, value buf, value signature) {
    secp256k1_ecdsa_signature_serialize_compact(Caml_ba_data_val(ctx),
                                                Caml_ba_data_val(buf),
                                                Caml_ba_data_val(signature));
    return Val_unit;
}

CAMLprim value ecdsa_recoverable_signature_parse_compact (value ctx, value buf, value signature, value recid) {
    return Val_bool(secp256k1_ecdsa_recoverable_signature_parse_compact (Caml_ba_data_val(ctx),
                                                                         Caml_ba_data_val(buf),
                                                                         Caml_ba_data_val(signature),
                                                                         Int_val(recid)));
}

CAMLprim value ecdsa_sign_recoverable (value ctx, value buf, value seckey, value msg) {
    return Val_bool(secp256k1_ecdsa_sign_recoverable (Caml_ba_data_val(ctx),
                                                      Caml_ba_data_val(buf),
                                                      Caml_ba_data_val(msg),
                                                      Caml_ba_data_val(seckey),
                                                      NULL, NULL));
}

CAMLprim value ecdsa_recoverable_signature_serialize_compact(value ctx, value buf, value signature) {
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(Caml_ba_data_val(ctx),
                                                            Caml_ba_data_val(buf),
                                                            &recid,
                                                            Caml_ba_data_val(signature));
    return Val_int(recid);
}

CAMLprim value ecdsa_recoverable_signature_convert(value ctx, value buf, value signature) {
    secp256k1_ecdsa_recoverable_signature_convert(Caml_ba_data_val(ctx),
                                                   Caml_ba_data_val(buf),
                                                   Caml_ba_data_val(signature));
    return Val_unit;
}

CAMLprim value ecdsa_recover(value ctx, value buf, value signature, value msg) {
    return Val_bool(secp256k1_ecdsa_recover(Caml_ba_data_val(ctx),
                                            Caml_ba_data_val(buf),
                                            Caml_ba_data_val(signature),
                                            Caml_ba_data_val(msg)));
}

value caml_secp256k1_xonly_pubkey_from_pubkey(value v_ctx, value v_pubkey, value v_out) {
  return Val_bool(secp256k1_xonly_pubkey_from_pubkey(Caml_ba_data_val(v_ctx),
                                                     Caml_ba_data_val(v_out),
                                                     NULL,
                                                     Caml_ba_data_val(v_pubkey)));
}

value caml_secp256k1_xonly_pubkey_parse(value v_ctx, value v_out, value v_input) {
  return Val_bool(secp256k1_xonly_pubkey_parse(Caml_ba_data_val(v_ctx),
                                               Caml_ba_data_val(v_out),
                                               Caml_ba_data_val(v_input)));
}

value caml_secp256k1_xonly_pubkey_serialize(value v_ctx, value v_out, value v_key) {
  return Val_bool(secp256k1_xonly_pubkey_serialize(Caml_ba_data_val(v_ctx),
                                                   Caml_ba_data_val(v_out),
                                                   Caml_ba_data_val(v_key)));
}

value caml_secp256k1_xonly_pubkey_cmp(value v_a, value v_b) {
  unsigned char buf_a[32], buf_b[32];
  secp256k1_xonly_pubkey_serialize(NULL, buf_a, Caml_ba_data_val(v_a));
  secp256k1_xonly_pubkey_serialize(NULL, buf_b, Caml_ba_data_val(v_b));
  return Val_int(memcmp(buf_a, buf_b, 32));
}

value caml_secp256k1_xonly_pubkey_tweak_add(value v_ctx, value v_out_pubkey, value v_xonly_pubkey, value v_tweak) {
  return Val_bool(secp256k1_xonly_pubkey_tweak_add(Caml_ba_data_val(v_ctx),
                                                   Caml_ba_data_val(v_out_pubkey),
                                                   Caml_ba_data_val(v_xonly_pubkey),
                                                   Caml_ba_data_val(v_tweak)));
}

value caml_secp256k1_xonly_pubkey_tweak_add_check(value v_ctx, value v_tweaked32, value v_parity, value v_internal, value v_tweak) {
  return Val_bool(secp256k1_xonly_pubkey_tweak_add_check(Caml_ba_data_val(v_ctx),
                                                         Caml_ba_data_val(v_tweaked32),
                                                         Int_val(v_parity),
                                                         Caml_ba_data_val(v_internal),
                                                         Caml_ba_data_val(v_tweak)));
}

value caml_secp256k1_keypair_create(value v_ctx, value v_keypair_out, value v_seckey) {
  return Val_bool(secp256k1_keypair_create(Caml_ba_data_val(v_ctx),
                                           Caml_ba_data_val(v_keypair_out),
                                           Caml_ba_data_val(v_seckey)));
}

value caml_secp256k1_keypair_pub(value v_ctx, value v_pubkey_out, value v_keypair) {
  return Val_bool(secp256k1_keypair_pub(Caml_ba_data_val(v_ctx),
                                        Caml_ba_data_val(v_pubkey_out),
                                        Caml_ba_data_val(v_keypair)));
}

value caml_secp256k1_keypair_sec(value v_ctx, value v_seckey_out, value v_keypair) {
  return Val_bool(secp256k1_keypair_sec(Caml_ba_data_val(v_ctx),
                                        Caml_ba_data_val(v_seckey_out),
                                        Caml_ba_data_val(v_keypair)));
}

value caml_secp256k1_keypair_xonly_pub(value v_ctx, value v_xonly_out, value v_keypair) {
  return Val_bool(secp256k1_keypair_xonly_pub(Caml_ba_data_val(v_ctx),
                                              Caml_ba_data_val(v_xonly_out),
                                              NULL,
                                              Caml_ba_data_val(v_keypair)));
}

value caml_secp256k1_keypair_xonly_tweak_add(value v_ctx, value v_keypair, value v_tweak) {
  return Val_bool(secp256k1_keypair_xonly_tweak_add(Caml_ba_data_val(v_ctx),
                                                    Caml_ba_data_val(v_keypair),
                                                    Caml_ba_data_val(v_tweak)));
}

value caml_secp256k1_schnorrsig_sign32(value v_ctx, value v_sig, value v_msg, value v_keypair, value v_aux) {
  const unsigned char *aux = Is_block(v_aux) ? Caml_ba_data_val(Field(v_aux, 0)) : NULL;
  return Val_bool(secp256k1_schnorrsig_sign32(Caml_ba_data_val(v_ctx),
                                              Caml_ba_data_val(v_sig),
                                              Caml_ba_data_val(v_msg),
                                              Caml_ba_data_val(v_keypair),
                                              aux));
}

value caml_secp256k1_schnorrsig_verify(value v_ctx, value v_sig, value v_msg, value v_xonly_pub) {
  return Val_bool(secp256k1_schnorrsig_verify(Caml_ba_data_val(v_ctx),
                                              Caml_ba_data_val(v_sig),
                                              Caml_ba_data_val(v_msg),
                                              Caml_ba_array_val(v_msg)->dim[0],
                                              Caml_ba_data_val(v_xonly_pub)));
}

value caml_secp256k1_tagged_sha256(value v_ctx, value v_out_hash32, value v_tag, value v_msg) {
  return Val_bool(secp256k1_tagged_sha256(Caml_ba_data_val(v_ctx),
                                          Caml_ba_data_val(v_out_hash32),
                                          Caml_ba_data_val(v_tag),
                                          Caml_ba_array_val(v_tag)->dim[0],
                                          Caml_ba_data_val(v_msg),
                                          Caml_ba_array_val(v_msg)->dim[0]));
}
