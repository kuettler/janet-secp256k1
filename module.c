#include <secp256k1.h>
#include <janet.h>

// static and never freed
static secp256k1_context* ctx;

static const JanetAbstractType secp256k1_pubkey_type = {
    "jsecp256k1/pubkey",
    NULL, // gc,
    NULL, // gcmark,
    NULL, // get,
    NULL, // put
    NULL, // marshal,
    NULL, // unmarshal,
    NULL, // tostring,
    NULL, // compare,
    NULL, // hash,
    NULL, // next,
    JANET_ATEND_NEXT
};

static const JanetAbstractType secp256k1_ecdsa_signature_type = {
    "jsecp256k1/ecdsa-signature",
    NULL, // gc,
    NULL, // gcmark,
    NULL, // get,
    NULL, // put
    NULL, // marshal,
    NULL, // unmarshal,
    NULL, // tostring,
    NULL, // compare,
    NULL, // hash,
    NULL, // next,
    JANET_ATEND_NEXT
};

JANET_FN(cfun_ec_pubkey_create,
         "(jsecp256k1/ec-pubkey-create seckey)",
         "Compute the public key for a secret key.") {
    janet_fixarity(argc, 1);
    const uint8_t *seckey = janet_getstring(argv, 0);
    if (janet_string_length(seckey) != 32) janet_panic("Secret key must be 32 bytes.");
    secp256k1_pubkey* pubkey = janet_abstract(&secp256k1_pubkey_type, sizeof(secp256k1_pubkey));
    int result = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    if (result == 0) return janet_wrap_nil();
    return janet_wrap_abstract(pubkey);
}

JANET_FN(cfun_ec_pubkey_parse,
         "(jsecp256k1/ec-pubkey-parse input)",
         "Parse a variable-length public key into the pubkey object.") {
    janet_fixarity(argc, 1);
    const uint8_t *input = janet_getstring(argv, 0);
    secp256k1_pubkey* pubkey = janet_abstract(&secp256k1_pubkey_type, sizeof(secp256k1_pubkey));
    int result = secp256k1_ec_pubkey_parse(ctx, pubkey, input, janet_string_length(input));
    if (result == 0) return janet_wrap_nil();
    return janet_wrap_abstract(pubkey);
}

JANET_FN(cfun_ec_pubkey_serialize,
         "(jsecp256k1/ec-pubkey-serialize pubkey)",
         "Serialize a pubkey object into a serialized byte sequence.") {
    janet_fixarity(argc, 1);
    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)janet_getabstract(argv, 0, &secp256k1_pubkey_type);
    size_t outputlen = 33;
    unsigned char *pubkey_output = janet_string_begin(outputlen);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_output, &outputlen, pubkey, SECP256K1_EC_COMPRESSED);
    janet_string_end(pubkey_output);
    return janet_wrap_string(pubkey_output);
}

JANET_FN(cfun_ec_seckey_tweak_add,
         "(jsecp256k1/ec-seckey-tweak-add seckey tweak32)",
         "Tweak a secret key by adding tweak to it.") {
    janet_fixarity(argc, 2);
    const uint8_t *seckey = janet_getstring(argv, 0);
    if (janet_string_length(seckey) != 32) janet_panic("Secret key must be 32 bytes.");
    const uint8_t *tweak32 = janet_getstring(argv, 1);
    if (janet_string_length(tweak32) != 32) janet_panic("Tweak string must be 32 bytes.");
    unsigned char *seckey_output = janet_string_begin(32);
    memcpy(seckey_output, seckey, 32);
    int result = secp256k1_ec_seckey_tweak_add(ctx, seckey_output, tweak32);
    if (result == 0) return janet_wrap_nil();
    janet_string_end(seckey_output);
    return janet_wrap_string(seckey_output);
}

JANET_FN(cfun_ec_seckey_verify,
         "(jsecp256k1/ec-seckey-verify seckey)",
         "Verify an ECDSA secret key.") {
    janet_fixarity(argc, 1);
    const uint8_t *seckey = janet_getstring(argv, 0);
    if (janet_string_length(seckey) != 32) janet_panic("Secret key must be 32 bytes.");
    int result = secp256k1_ec_seckey_verify(ctx, seckey);
    return janet_wrap_boolean(result);
}

JANET_FN(cfun_ecdsa_sign,
         "(jsecp256k1/ec-ecdsa-sign msghash32 seckey)",
         "Create an ECDSA signature.") {
    janet_fixarity(argc, 2);
    const uint8_t *msghash32 = janet_getstring(argv, 0);
    if (janet_string_length(msghash32) != 32) janet_panic("Message hash must be 32 bytes.");
    const uint8_t *seckey = janet_getstring(argv, 1);
    if (janet_string_length(seckey) != 32) janet_panic("Secret key must be 32 bytes.");
    secp256k1_ecdsa_signature* signature = janet_abstract(&secp256k1_ecdsa_signature_type, sizeof(secp256k1_ecdsa_signature));
    int result = secp256k1_ecdsa_sign(ctx, signature, msghash32, seckey, NULL, NULL);
    if (result == 0) return janet_wrap_nil();
    return janet_wrap_abstract(signature);
}

JANET_FN(cfun_ecdsa_signature_normalize,
         "(jsecp256k1/ecdsa-signature-normalize sigin)",
         "Convert a signature to a normalized lower-S form.") {
    janet_fixarity(argc, 1);
    const secp256k1_ecdsa_signature* sigin = (secp256k1_ecdsa_signature*)janet_getabstract(argv, 0, &secp256k1_ecdsa_signature_type);
    secp256k1_ecdsa_signature* signature = janet_abstract(&secp256k1_ecdsa_signature_type, sizeof(secp256k1_ecdsa_signature));
    int result = secp256k1_ecdsa_signature_normalize(ctx, signature, sigin);
    if (result == 0) return argv[0];
    return janet_wrap_abstract(signature);
}

JANET_FN(cfun_ecdsa_signature_parse_der,
         "(jsecp256k1/ecdsa-signature-parse-der input)",
         "Parse a DER ECDSA signature.") {
    janet_fixarity(argc, 1);
    const uint8_t *input = janet_getstring(argv, 0);
    secp256k1_ecdsa_signature* signature = janet_abstract(&secp256k1_ecdsa_signature_type, sizeof(secp256k1_ecdsa_signature));
    int result = secp256k1_ecdsa_signature_parse_der(ctx, signature, input, janet_string_length(input));
    if (result == 0) return janet_wrap_nil();
    return janet_wrap_abstract(signature);
}

JANET_FN(cfun_ecdsa_signature_serialize_der,
         "(jsecp256k1/ecdsa-signature-serialize-der signature)",
         "Serialize an ECDSA signature in DER format.") {
    janet_fixarity(argc, 1);
    const secp256k1_ecdsa_signature* signature = (secp256k1_ecdsa_signature*)janet_getabstract(argv, 0, &secp256k1_ecdsa_signature_type);
    size_t outputlen = 128;
    unsigned char output[outputlen];
    int result = secp256k1_ecdsa_signature_serialize_der(ctx, output, &outputlen, signature);
    if (result == 0) return janet_wrap_nil();
    return janet_wrap_string(janet_string(output, outputlen));
}

JANET_FN(cfun_ecdsa_verify,
         "(jsecp256k1/ecdsa-verify signature msghash32 pubkey)",
         "Verify an ECDSA signature.") {
    janet_fixarity(argc, 3);
    const secp256k1_ecdsa_signature* signature = (secp256k1_ecdsa_signature*)janet_getabstract(argv, 0, &secp256k1_ecdsa_signature_type);
    const uint8_t *msghash32 = janet_getstring(argv, 1);
    if (janet_string_length(msghash32) != 32) janet_panic("Message hash must be 32 bytes.");
    secp256k1_pubkey* pubkey = (secp256k1_pubkey*)janet_getabstract(argv, 2, &secp256k1_pubkey_type);
    int result = secp256k1_ecdsa_verify(ctx, signature, msghash32, pubkey);
    return janet_wrap_boolean(result);
}

JANET_MODULE_ENTRY(JanetTable *env) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    JanetRegExt cfuns[] = {
        JANET_REG("ec-ecdsa-sign", cfun_ecdsa_sign),
        JANET_REG("ec-pubkey-create", cfun_ec_pubkey_create),
        JANET_REG("ec-pubkey-parse", cfun_ec_pubkey_parse),
        JANET_REG("ec-pubkey-serialize", cfun_ec_pubkey_serialize),
        JANET_REG("ec-seckey-tweak-add", cfun_ec_seckey_tweak_add),
        JANET_REG("ec-seckey-verify", cfun_ec_seckey_verify),
        JANET_REG("ecdsa-signature-normalize", cfun_ecdsa_signature_normalize),
        JANET_REG("ecdsa-signature-parse-der", cfun_ecdsa_signature_parse_der),
        JANET_REG("ecdsa-signature-serialize-der", cfun_ecdsa_signature_serialize_der),
        JANET_REG("ecdsa-verify", cfun_ecdsa_verify),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "jsecp256k1", cfuns);
    janet_register_abstract_type(&secp256k1_pubkey_type);
    janet_register_abstract_type(&secp256k1_ecdsa_signature_type);
}
