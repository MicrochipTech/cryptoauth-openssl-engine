/**
 * \brief OpenSSL Engine for ATECCx08 devices - Internal functions and structures
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ECCX08_ENGINE_INTERNAL_H__
#define __ECCX08_ENGINE_INTERNAL_H__

#include "atcacert/atcacert_def.h"

#if 0
#if OPENSSL_VERSION_NUMBER > 0x10002000 && OPENSSL_VERSION_NUMBER < 0x10003000
/** From crypto/ecdh/ech_locl.h (OpenSSL 1.0.2) */
struct ecdh_method {
    const char *name;
    int(*compute_key) (void *key, size_t outlen, const EC_POINT *pub_key,
        EC_KEY *ecdh, void *(*KDF) (const void *in,
            size_t inlen, void *out,
            size_t *outlen));
    int flags;
    char *app_data;
};

///** From crypto/ecdsa/ecs_locl.h (OpenSSL 1.0.2) */
//struct ecdsa_method {
//    const char *name;
//    ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
//        const BIGNUM *inv, const BIGNUM *rp,
//        EC_KEY *eckey);
//    int(*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
//        BIGNUM **r);
//    int(*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
//        const ECDSA_SIG *sig, EC_KEY *eckey);
//    int flags;
//    void *app_data;
//};

///** From crypto/ec/ec_lcl.h (OpenSSL 1.0.2) */
//struct ec_point_st {
//    const EC_METHOD *meth;
//    /*
//    * All members except 'meth' are handled by the method functions, even if
//    * they appear generic
//    */
//    BIGNUM X;
//    BIGNUM Y;
//    BIGNUM Z;                   /* Jacobian projective coordinates: (X, Y, Z)
//                                * represents (X/Z^2, Y/Z^3) if Z != 0 */
//    int Z_is_one;               /* enable optimized point arithmetics for
//                                * special case */
//} /* EC_POINT */;
//
///** From crypto/ec/ec_lcl.h (OpenSSL 1.0.2) */
//typedef struct ec_extra_data_st {
//    struct ec_extra_data_st *next;
//    void *data;
//    void *(*dup_func) (void *);
//    void(*free_func) (void *);
//    void(*clear_free_func) (void *);
//} EC_EXTRA_DATA;
//
///** From crypto/ec/ec_lcl.h (OpenSSL 1.0.2) */
//struct ec_key_st {
//    int version;
//    EC_GROUP *group;
//    EC_POINT *pub_key;
//    BIGNUM *priv_key;
//    unsigned int enc_flag;
//    point_conversion_form_t conv_form;
//    int references;
//    int flags;
//    EC_EXTRA_DATA *method_data;
//};

/** From crypto/evp/evp_locl.h (OpenSSL 1.0.2) */
struct evp_pkey_method_st {
    int pkey_id;
    int flags;
    int(*init) (EVP_PKEY_CTX *ctx);
    int(*copy) (EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
    void(*cleanup) (EVP_PKEY_CTX *ctx);
    int(*paramgen_init) (EVP_PKEY_CTX *ctx);
    int(*paramgen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*keygen_init) (EVP_PKEY_CTX *ctx);
    int(*keygen) (EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
    int(*sign_init) (EVP_PKEY_CTX *ctx);
    int(*sign) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        const unsigned char *tbs, size_t tbslen);
    int(*verify_init) (EVP_PKEY_CTX *ctx);
    int(*verify) (EVP_PKEY_CTX *ctx,
        const unsigned char *sig, size_t siglen,
        const unsigned char *tbs, size_t tbslen);
    int(*verify_recover_init) (EVP_PKEY_CTX *ctx);
    int(*verify_recover) (EVP_PKEY_CTX *ctx,
        unsigned char *rout, size_t *routlen,
        const unsigned char *sig, size_t siglen);
    int(*signctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int(*signctx) (EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
        EVP_MD_CTX *mctx);
    int(*verifyctx_init) (EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
    int(*verifyctx) (EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
        EVP_MD_CTX *mctx);
    int(*encrypt_init) (EVP_PKEY_CTX *ctx);
    int(*encrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);
    int(*decrypt_init) (EVP_PKEY_CTX *ctx);
    int(*decrypt) (EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
        const unsigned char *in, size_t inlen);
    int(*derive_init) (EVP_PKEY_CTX *ctx);
    int(*derive) (EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
    int(*ctrl) (EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
    int(*ctrl_str) (EVP_PKEY_CTX *ctx, const char *type, const char *value);
} /* EVP_PKEY_METHOD */;

/** From crypto/evp/evp_locl.h (OpenSSL 1.0.2) */
struct evp_pkey_ctx_st {
    /* Method associated with this operation */
    const EVP_PKEY_METHOD *pmeth;
    /* Engine that implements this method or NULL if builtin */
    ENGINE *engine;
    /* Key: may be NULL */
    EVP_PKEY *pkey;
    /* Peer key for key agreement, may be NULL */
    EVP_PKEY *peerkey;
    /* Actual operation */
    int operation;
    /* Algorithm specific data */
    void *data;
    /* Application specific data */
    void *app_data;
    /* Keygen callback */
    EVP_PKEY_gen_cb *pkey_gencb;
    /* implementation specific keygen data */
    int *keygen_info;
    int keygen_info_count;
} /* EVP_PKEY_CTX */;
#else
#error "OpenSSL 1.1.x is not yet supported by this engine"
#endif  //OPENSSL_VERSION_NUMBER
#endif  //ATCA_OPENSSL_ENGINE_INTERNAL_HEADERS

/* Global Configuration Structures */
extern ATCAIfaceCfg *       pCfg;
extern atcacert_def_t *     g_cert_def_1_signer_ptr;
extern atcacert_def_t *     g_cert_def_2_device_ptr;
extern uint8_t        g_signer_1_ca_public_key[64];

typedef struct _eccx08_engine_config
{
    /** Private key slot */
    uint8_t     device_key_slot;
    /** ECDH key slot (or base slot if more than one is used) */
    uint8_t     ecdh_key_slot;
    /** 0 - ECDH disabled, 1 - Enabled, >1 Used for wear leveling on ATECC508A */
    uint8_t     ecdh_key_count;     
} eccx08_engine_config_t;
extern eccx08_engine_config_t eccx08_engine_config;

/* Global Engine Structures */
extern const ENGINE_CMD_DEFN eccx08_cmd_defns[];
extern RAND_METHOD eccx08_rand;

/* Library Module Initialization Functions */
int eccx08_ameth_init(void); 
int eccx08_cert_init(void);
int eccx08_cipher_init(void);
int eccx08_ecdh_init(void);
int eccx08_ecdsa_init(ECDSA_METHOD**);
int eccx08_pkey_meth_init(void);
int eccx08_platform_init(void);
int eccx08_rand_init(void);

/* Library Module Cleanup Functions */
int eccx08_ameth_cleanup(void);
int eccx08_cert_cleanup(void);
int eccx08_ecdsa_cleanup(void);
int eccx08_pkey_meth_cleanup(void);

/* Certificate Manipulation */
atcacert_def_t * eccx08_cert_new(size_t size, size_t elements);
atcacert_def_t * eccx08_cert_copy(atcacert_def_t * pCertOrig);
int eccx08_cert_free(void* cert);
int eccx08_cert_load_client(ENGINE *, SSL *, STACK_OF(X509_NAME) *, X509 **,
    EVP_PKEY **, STACK_OF(X509) **, UI_METHOD *, void *);
ATCA_STATUS eccx08_cert_load_pubkey(const atcacert_def_t* def, const uint8_t keyout[64]);

/* SHA256 */
int eccx08_sha256_selector(ENGINE *, const EVP_MD **, const int **, int );

/* PKEY */
EVP_PKEY* eccx08_load_pubkey(ENGINE *, const char *, UI_METHOD *, void *);
int eccx08_pmeth_selector(ENGINE *, EVP_PKEY_METHOD **, const int **, int);

/* ASN1 PKEY */
int eccx08_ameth_selector(ENGINE *, EVP_PKEY_ASN1_METHOD **, const int **, int);


#endif /* __ECCX08_ENGINE_INTERNAL_H__ */

